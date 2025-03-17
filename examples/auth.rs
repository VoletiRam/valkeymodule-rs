use std::os::raw::c_int;
use std::fmt;
use valkey_module::alloc::ValkeyAlloc;
use valkey_module::{
    valkey_module, Context, ValkeyString, AUTH_HANDLED, AUTH_NOT_HANDLED, Status, ValkeyError
};

#[derive(Debug)]
enum AuthResult {
    Allow,
    Deny,
    Next
}

#[derive(Debug)]
struct AuthPrivData {
    result: AuthResult
}

// Implement Display for AuthResult
impl fmt::Display for AuthResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthResult::Allow => write!(f, "Allow"),
            AuthResult::Deny => write!(f, "Deny"),
            AuthResult::Next => write!(f, "Next"),
        }
    }
}

// Example of a simple auth callback that module owners would write
fn auth_callback(ctx: &Context, username: ValkeyString, password: ValkeyString) -> Result<c_int, ValkeyError> {
    ctx.log_notice(&format!("Auth attempt for user: {}, password: {}", username.to_string(), password.to_string()));

    if username.to_string() == "foo" && password.to_string() == "allow" {
        ctx.log_notice("Matched foo user credentials");
        match ctx.authenticate_client_with_acl_user(&username) {
            Status::Ok => {
                ctx.log_notice("Successfully authenticated foo user");
                Ok(AUTH_HANDLED)
            },
            Status::Err => {
                ctx.log_warning("Failed to authenticate foo user with ACL");
                Ok(AUTH_HANDLED)
            }
        }
    } else {
        ctx.log_notice(&format!("Auth not handled for user: {}", username.to_string()));
        Ok(AUTH_NOT_HANDLED)
    }
}

fn bar_auth_callback(ctx: &Context, username: ValkeyString, password: ValkeyString) -> Result<c_int, ValkeyError> {
    ctx.log_notice(&format!("Bar auth attempt for user: {}, password: {}", username.to_string(), password.to_string()));

    if username.to_string() == "bar" && password.to_string() == "secret" {
        ctx.log_notice("Matched bar user credentials");
        match ctx.authenticate_client_with_acl_user(&username) {
            Status::Ok => {
                ctx.log_notice("Successfully authenticated bar user with ACL");
                Ok(AUTH_HANDLED)
            },
            Status::Err => {
                ctx.log_warning("Failed to authenticate bar user with ACL");
                Ok(AUTH_HANDLED)
            }
        }
    } else {
        ctx.log_notice(&format!("Bar auth not handled for user: {}", username.to_string()));
        Ok(AUTH_NOT_HANDLED)
    }
}

fn admin_auth_callback(ctx: &Context, username: ValkeyString, password: ValkeyString) -> Result<c_int, ValkeyError> {
    ctx.log_notice(&format!("Admin auth attempt for user: {}, password: {}", username.to_string(), password.to_string()));

    if username.to_string() == "admin" && password.to_string() == "superSecret123" {
        ctx.log_notice("Matched admin user credentials");
        match ctx.authenticate_client_with_acl_user(&username) {
            Status::Ok => {
                ctx.log_notice("Successfully authenticated admin user");
                Ok(AUTH_HANDLED)
            },
            Status::Err => {
                ctx.log_warning("Failed to authenticate admin user with ACL");
                Ok(AUTH_NOT_HANDLED)
            }
        }
    } else {
        ctx.log_notice(&format!("Admin auth not handled for user: {}", username.to_string()));
        Ok(AUTH_NOT_HANDLED)
    }
}

// Core auth reply logic
fn my_auth_reply(name: &str, ctx: &Context, username: ValkeyString, _password: ValkeyString) -> Result<c_int, ValkeyError> {
    match ctx.get_blocked_client_privdata::<AuthPrivData>() {
        Some(priv_data) => {
            match priv_data.result {
                AuthResult::Allow => {
                    ctx.log_notice(&format!("{}: Auth allowed for user: {}", name, username.to_string()));
                    match ctx.authenticate_client_with_acl_user(&username) {
                        Status::Ok => {
                            ctx.log_notice(&format!("{}: Successfully authenticated user: {}", name, username.to_string()));
                            Ok(AUTH_HANDLED)
                        },
                        Status::Err => {
                            ctx.log_warning(&format!("{}: Failed to authenticate user: {} with ACL", name, username.to_string()));
                            Ok(AUTH_HANDLED)
                        }
                    }
                },
                AuthResult::Deny => {
                    ctx.log_notice(&format!("{}: Auth explicitly denied for user: {}", name, username.to_string()));
                    Ok(AUTH_HANDLED)
                },
                AuthResult::Next => {
                    ctx.log_notice(&format!("{}: Passing auth to next handler for user: {}", name, username.to_string()));
                    Ok(AUTH_NOT_HANDLED)
                }
            }
        },
        None => {
            ctx.log_warning(&format!("{}: No private data found in auth reply", name));
            Ok(AUTH_NOT_HANDLED)
        }
    }
}


fn my_auth_reply_one(ctx: &Context, username: ValkeyString, password: ValkeyString) -> Result<c_int, ValkeyError> {
    my_auth_reply("auth_one", ctx, username, password)
}

fn my_auth_reply_two(ctx: &Context, username: ValkeyString, password: ValkeyString) -> Result<c_int, ValkeyError> {
    my_auth_reply("auth_two", ctx, username, password)
}

fn my_free_privdata_callback(_ctx: &Context, data: AuthPrivData) {
    // Handle cleanup with typed data
    println!("my_free_privdata_callback: Cleaning up: {}", data.result);
}

fn my_free_privdata_callback_two(_ctx: &Context, data: AuthPrivData) {
    // Handle cleanup with typed data
    println!("my_free_privdata_callback_two: Cleaning up: {}", data.result);
}


fn blocking_auth_callback(
    ctx: &Context,
    username: ValkeyString,
    password: ValkeyString
) -> Result<c_int, ValkeyString> {
    ctx.log_notice("blocking_auth_callback: handling blocked client");

    let username_str = username.to_string();
    let password_str = password.to_string();

     // Create blocked client without free callback
     let mut blocked_client = ctx.block_client_on_auth(my_auth_reply_one, Some(my_free_privdata_callback));

    // For default user, return AUTH_HANDLED to let Valkey handle it
    if username.to_string() == "default" {
        ctx.log_notice("Default user authentication - passing to next handler");
        if let Err(_) = ctx.abort_block(blocked_client) {
            // Create ValkeyString properly
            return Err(ValkeyString::create(None, "Failed to abort blocked client"));
        }
        return Ok(AUTH_HANDLED);
    }


    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2));

        let result = match (username_str.as_str(), password_str.as_str()) {
            ("abc", "allow") => AuthResult::Allow,
            ("def", "secret") => AuthResult::Allow,
            ("ghk", "superSecret123") => AuthResult::Allow,
            ("abc", _) | ("def", _) | ("ghk", _) => AuthResult::Deny,
            _ => AuthResult::Next
        };

        blocked_client.set_private_data(AuthPrivData { result });

        drop(blocked_client);
    });

    Ok(AUTH_HANDLED)
}

fn blocking_auth_callback_two(
    ctx: &Context,
    username: ValkeyString,
    password: ValkeyString
) -> Result<c_int, ValkeyString> {
    ctx.log_notice("blocking_auth_callback_two: handling blocked client");

    let username_str = username.to_string();
    let password_str = password.to_string();

     // Create blocked client without free callback
     let mut blocked_client = ctx.block_client_on_auth(my_auth_reply_two, Some(my_free_privdata_callback_two));

    // For default user, return AUTH_NOT_HANDLED to let Valkey handle it
    if username.to_string() == "default" {
        ctx.log_notice("blocking_auth_callback_two: Default user authentication - passing to next handler");
        if let Err(_) = ctx.abort_block(blocked_client) {
            // Create ValkeyString properly
            return Err(ValkeyString::create(None, "Failed to abort blocked client"));
        }
        return Ok(AUTH_HANDLED);
    }


    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2));

        let result = match (username_str.as_str(), password_str.as_str()) {
            ("ref", "allow") => AuthResult::Allow,
            ("def", "secret") => AuthResult::Allow,
            ("puf", "superSecret123") => AuthResult::Allow,
            ("ref", _) | ("def", _) | ("puf", _) => AuthResult::Deny,
            _ => AuthResult::Next
        };

        blocked_client.set_private_data(AuthPrivData { result });

        drop(blocked_client);
    });

    Ok(AUTH_HANDLED)
}

//////////////////////////////////////////////////////

valkey_module! {
    name: "auth",
    version: 1,
    allocator: (ValkeyAlloc, ValkeyAlloc),
    data_types: [],
    auth: [
        blocking_auth_callback_two,
        auth_callback,
        bar_auth_callback,
        admin_auth_callback,
        blocking_auth_callback
    ],
    commands: []
}
