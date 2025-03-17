use std::ptr;
use std::any::Any;
use std::any::TypeId;
use std::os::raw::{c_void, c_int};
use crate::redismodule::{AUTH_HANDLED, AUTH_NOT_HANDLED};
use crate::{raw, Context, ValkeyString, ValkeyError};
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;

pub type AuthReplyCallback = fn(&Context, ValkeyString, ValkeyString) -> Result<c_int, ValkeyError>;
type FreePrivDataCallback<T> = fn(&Context, T);

// Static storage mapping TypeId to the callback using Lazy and Mutex
static FREE_PRIV_CALLBACKS: Lazy<Mutex<HashMap<TypeId, Box<dyn Fn(&Context, *mut c_void) + Send + Sync>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static mut AUTH_REPLY_CALLBACK: Option<AuthReplyCallback> = None;


pub struct BlockedClient {
    pub(crate) inner: *mut raw::RedisModuleBlockedClient,
    private_data: Option<Box<dyn Any + Send>>,
}

pub extern "C" fn raw_callback<T: 'static>(ctx: *mut raw::RedisModuleCtx, data: *mut c_void) {
    let ctx = &Context::new(ctx);

    if data.is_null() {
        ctx.log_debug("[callback] Data is null; this should not happen!");
        return;
    }

    if let Ok(callbacks) = FREE_PRIV_CALLBACKS.lock() {
        if let Some(callback) = callbacks.get(&TypeId::of::<T>()) {
            callback(ctx, data);
        }
    }
}

pub unsafe extern "C" fn reply_callback_wrapper(
    ctx: *mut raw::RedisModuleCtx,
    username: *mut raw::RedisModuleString,
    password: *mut raw::RedisModuleString,
    err: *mut *mut raw::RedisModuleString,
) -> c_int {
    let context = Context::new(ctx);
    let ctx_ptr = std::ptr::NonNull::new_unchecked(ctx);

    let username = ValkeyString::new(Some(ctx_ptr), username);
    let password = ValkeyString::new(Some(ctx_ptr), password);

    if let Some(callback) = AUTH_REPLY_CALLBACK {
        match callback(&context, username, password) {
            Ok(result) => result,
            Err(e) => {
                if !err.is_null() {
                    let error_msg = ValkeyString::create(None, e.to_string().as_str());
                    *err = error_msg.into_raw();
                }
                AUTH_HANDLED
            }
        }
    } else {
        AUTH_NOT_HANDLED
    }
}

// We need to be able to send the inner pointer to another thread
unsafe impl Send for BlockedClient {}

impl BlockedClient {
    pub(crate) fn new(inner: *mut raw::RedisModuleBlockedClient) -> Self {
        Self {
            inner,
            private_data: None,
        }
    }

    pub fn set_private_data<T: Any + Send>(&mut self, data: T) {
        self.private_data = Some(Box::new(data));
    }
}

impl Drop for BlockedClient {
    fn drop(&mut self) {
        let privdata = self.private_data.take().map_or(ptr::null_mut(), |data| {
            Box::into_raw(data) as *mut std::ffi::c_void
        });

        unsafe {
            raw::RedisModule_UnblockClient.unwrap()(self.inner, privdata);
            // No need for explicit drop since take() already cleared self.private_data
        };
    }
}

impl Context {
    #[must_use]
    pub fn block_client(&self) -> BlockedClient {
        let blocked_client = unsafe {
            raw::RedisModule_BlockClient.unwrap()(
                self.ctx, // ctx
                None,     // reply_func
                None,     // timeout_func
                None, 0,
            )
        };

        BlockedClient::new(blocked_client)
    }

    #[must_use]
    pub fn block_client_on_auth<T: 'static>(
        &self,
        auth_reply_callback: AuthReplyCallback,
        free_privdata_callback: Option<FreePrivDataCallback<T>>,
    ) -> BlockedClient {
        unsafe {
            AUTH_REPLY_CALLBACK = Some(auth_reply_callback);
            
            if let Some(callback) = free_privdata_callback {
                // Create a wrapper that handles the type conversion
                let wrapper = Box::new(move |ctx: &Context, data: *mut c_void| {
                    let typed_data = data as *mut T;
                    let value = ptr::read(typed_data);
                    callback(ctx, value);
                }) as Box<dyn Fn(&Context, *mut c_void) + Send + Sync>;
                
                if let Ok(mut callbacks) = FREE_PRIV_CALLBACKS.lock() {
                    callbacks.insert(TypeId::of::<T>(), wrapper);
                }
            }

            let blocked_client = raw::RedisModule_BlockClientOnAuth.unwrap()(
                self.ctx,
                Some(reply_callback_wrapper),
                Some(raw_callback::<T>),
            );

            BlockedClient::new(blocked_client)
        }
    }

    #[must_use]
    pub fn abort_block(
        &self,
        blocked_client: BlockedClient
    ) -> Result<c_int, ValkeyError> {
        let result = unsafe {
            raw::RedisModule_AbortBlock.unwrap()(blocked_client.inner)
        };

        if result == raw::REDISMODULE_OK as c_int {
            Ok(result)
        } else {

            Err(ValkeyError::short_read())
            //Err(ValkeyError::Str("Failed creating stream iterator"))
        }
    }
}