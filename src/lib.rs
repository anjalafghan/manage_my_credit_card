use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::{components::*, *};

#[cfg(feature = "ssr")]
pub mod auth;
#[cfg(feature = "ssr")]
pub mod db;

//
// ───────────────────── Hydrate entrypoint (client) ─────────────────────
//

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}

//
// ─────────────────────────── App & Routes ───────────────────────────
//

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/manage_my_credit_card.css"/>
        <Title text="Leptos Auth Demo"/>

        <Router>
            <main>
                <Routes fallback=|| "Page not found".into_view()>
                    <Route path=StaticSegment("") view=HomePage/>
                    <Route path=StaticSegment("login") view=LoginPage/>
                    <Route path=StaticSegment("register") view=RegisterPage/>
                    <Route path=StaticSegment("dashboard") view=DashboardPage/>
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    view! {
        <div class="container">
            <h1>"Welcome to Leptos Auth Demo"</h1>
            <div class="links">
                <a href="/login">"Login"</a>
                <a href="/register">"Register"</a>
            </div>
        </div>
    }
}

//
// ─────────────────────── Browser-side helpers ───────────────────────
//

#[cfg(not(feature = "ssr"))]
fn write_token_to_local_storage(token: &str) {
    use leptos::logging::log;
    use leptos::web_sys;

    if let Some(window) = web_sys::window() {
        match window.local_storage() {
            Ok(Some(storage)) => {
                if storage.set_item("token", token).is_err() {
                    log!("Auth: failed to write token to localStorage");
                } else {
                    log!("Auth: token stored in localStorage, len={}", token.len());
                }
            }
            Ok(None) => log!("Auth: localStorage not available"),
            Err(_) => log!("Auth: error accessing localStorage"),
        }
    }
}

#[cfg(not(feature = "ssr"))]
fn read_token_from_local_storage() -> Result<String, String> {
    use leptos::logging::log;
    use leptos::web_sys;

    let window = web_sys::window().ok_or_else(|| "No window object".to_string())?;
    let storage = window
        .local_storage()
        .map_err(|_| "Error accessing localStorage".to_string())?
        .ok_or_else(|| "localStorage not available".to_string())?;

    let token = storage
        .get_item("token")
        .map_err(|_| "Failed to read token from localStorage".to_string())?
        .ok_or_else(|| "No token in localStorage".to_string())?;

    log!("Auth: read token from localStorage, len={}", token.len());
    Ok(token)
}

#[cfg(not(feature = "ssr"))]
fn clear_token_from_local_storage() {
    use leptos::logging::log;
    use leptos::web_sys;

    if let Some(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            if storage.remove_item("token").is_ok() {
                log!("Auth: token removed from localStorage");
            }
        }
    }
}

#[cfg(not(feature = "ssr"))]
fn redirect_to(path: &str) {
    use leptos::web_sys;

    if let Some(window) = web_sys::window() {
        let _ = window.location().set_href(path);
    }
}

#[cfg(not(feature = "ssr"))]
pub fn logout() {
    use leptos::logging::log;

    log!("Auth: logout called, removing token and redirecting to /login");
    clear_token_from_local_storage();
    redirect_to("/login");
}

#[cfg(feature = "ssr")]
pub fn logout() {
    // No-op on server
}

//
// ───────────────────────── Login / Register ─────────────────────────
//

#[component]
fn LoginPage() -> impl IntoView {
    let (username, set_username) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (error, set_error) = signal(None::<String>);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        #[cfg(not(feature = "ssr"))]
        leptos::logging::log!("Login form submitted for: {}", username.get());

        set_loading.set(true);
        set_error.set(None);

        let username_val = username.get();
        let password_val = password.get();

        leptos::task::spawn_local(async move {
            let result = login(username_val.clone(), password_val.clone()).await;

            #[cfg(not(feature = "ssr"))]
            leptos::logging::log!("Login result: {:?}", result.is_ok());

            match result {
                Ok(token) => {
                    #[cfg(not(feature = "ssr"))]
                    {
                        leptos::logging::log!("Login successful, storing token & redirecting");
                        write_token_to_local_storage(&token);
                        redirect_to("/dashboard");
                    }
                }
                Err(e) => {
                    set_error.set(Some(e.to_string()));
                }
            }

            set_loading.set(false);
        });
    };

    view! {
        <div class="container">
            <div class="form-container">
                <h1>"Login"</h1>
                {move || error.get().map(|e| view! { <div class="error">{e}</div> })}
                <form on:submit=on_submit>
                    <input
                        type="text"
                        placeholder="Username"
                        on:input=move |ev| set_username.set(event_target_value(&ev))
                        prop:value=move || username.get()
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        on:input=move |ev| set_password.set(event_target_value(&ev))
                        prop:value=move || password.get()
                    />
                    <button type="submit" disabled=move || loading.get()>
                        {move || if loading.get() { "Loading..." } else { "Login" }}
                    </button>
                </form>
                <p>"Don't have an account? " <a href="/register">"Register"</a></p>
            </div>
        </div>
    }
}

#[component]
fn RegisterPage() -> impl IntoView {
    let (username, set_username) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (error, set_error) = signal(None::<String>);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        #[cfg(not(feature = "ssr"))]
        leptos::logging::log!("Register form submitted for: {}", username.get());

        set_loading.set(true);
        set_error.set(None);

        let username_val = username.get();
        let password_val = password.get();

        leptos::task::spawn_local(async move {
            let result = register(username_val.clone(), password_val.clone()).await;

            #[cfg(not(feature = "ssr"))]
            leptos::logging::log!("Register result: {:?}", result.is_ok());

            match result {
                Ok(_) => {
                    #[cfg(not(feature = "ssr"))]
                    {
                        leptos::logging::log!("Registration successful, redirecting to login");
                        redirect_to("/login");
                    }
                }
                Err(e) => {
                    set_error.set(Some(e.to_string()));
                }
            }

            set_loading.set(false);
        });
    };

    view! {
        <div class="container">
            <div class="form-container">
                <h1>"Register"</h1>
                {move || error.get().map(|e| view! { <div class="error">{e}</div> })}
                <form on:submit=on_submit>
                    <input
                        type="text"
                        placeholder="Username"
                        on:input=move |ev| set_username.set(event_target_value(&ev))
                        prop:value=move || username.get()
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        on:input=move |ev| set_password.set(event_target_value(&ev))
                        prop:value=move || password.get()
                    />
                    <button type="submit" disabled=move || loading.get()>
                        {move || if loading.get() { "Loading..." } else { "Register" }}
                    </button>
                </form>
                <p>"Already have an account? " <a href="/login">"Login"</a></p>
            </div>
        </div>
    }
}

//
// ─────────────────────────── Dashboard ───────────────────────────
//

#[component]
fn DashboardPage() -> impl IntoView {
    let (username, set_username) = signal(None::<String>);
    let (error, set_error) = signal(None::<String>);

    // Client-side: fetch user info using token from localStorage
    #[cfg(not(feature = "ssr"))]
    {
        use leptos::logging::log;

        let set_username = set_username.clone();
        let set_error = set_error.clone();

        leptos::task::spawn_local(async move {
            log!("Dashboard: starting client-side user info fetch");

            let token = match read_token_from_local_storage() {
                Ok(t) => t,
                Err(msg) => {
                    log!("Dashboard: token error: {}", msg);
                    set_error.set(Some(msg));
                    return;
                }
            };

            match get_user_info(token).await {
                Ok(info) => {
                    log!("Dashboard: get_user_info OK for user {}", info.username);
                    set_username.set(Some(info.username));
                }
                Err(e) => {
                    log!("Dashboard: get_user_info ERROR: {:?}", e);
                    set_error.set(Some(format!("{e}")));
                }
            }
        });
    }

    view! {
        <div class="container">
            <div class="dashboard">
                <h1>"Dashboard"</h1>

                {move || {
                    if let Some(name) = username.get() {
                        // ✅ Loaded successfully
                        view! {
                            <div>
                                <p>"Welcome, " {name} "!"</p>
                                <button on:click={
                                    let set_username = set_username.clone();
                                    let set_error = set_error.clone();
                                    move |_| {
                                        set_username.set(None);
                                        set_error.set(Some("You have been logged out.".to_string()));
                                        logout();
                                    }
                                }>"Logout"</button>
                            </div>
                        }.into_any()
                    } else if let Some(err) = error.get() {
                        // ❌ Error state
                        view! {
                            <div class="error">
                                <p>"Error loading user info."</p>
                                <p>"Details: " {err}</p>
                            </div>
                        }.into_any()
                    } else {
                        // ⏳ Loading state (initial SSR + early client)
                        view! {
                            <p>"Loading user info..."</p>
                        }.into_any()
                    }
                }}
            </div>
        </div>
    }
}

//
// ───────────────────── Server functions & types ─────────────────────
//

#[server(Login, "/api")]
pub async fn login(username: String, password: String) -> Result<String, ServerFnError> {
    use crate::auth::authenticate_user;
    use crate::db::get_db_pool;

    log::info!("Login attempt for user: {}", username);

    let pool = get_db_pool()
        .await
        .map_err(|e| ServerFnError::new(format!("Database error: {}", e)))?;

    let token = authenticate_user(&pool, &username, &password)
        .await
        .map_err(|e| {
            log::warn!("Login failed for {}: {}", username, e);
            ServerFnError::new(e)
        })?;

    log::info!("Login successful for user: {}", username);
    Ok(token)
}

#[server(Register, "/api")]
pub async fn register(username: String, password: String) -> Result<(), ServerFnError> {
    use crate::auth::create_user;
    use crate::db::get_db_pool;

    log::info!("Registration attempt for user: {}", username);

    let pool = get_db_pool()
        .await
        .map_err(|e| ServerFnError::new(format!("Database error: {}", e)))?;

    create_user(&pool, &username, &password)
        .await
        .map_err(|e| {
            log::warn!("Registration failed for {}: {}", username, e);
            ServerFnError::new(e)
        })?;

    log::info!("Registration successful for user: {}", username);
    Ok(())
}

#[server(GetUserInfo, "/api")]
pub async fn get_user_info(token: String) -> Result<UserInfo, ServerFnError> {
    use crate::auth::verify_token;

    log::info!("GetUserInfo: called with token length {}", token.len());

    match verify_token(&token) {
        Ok(claims) => {
            log::info!("GetUserInfo: token valid for user {}", claims.sub);
            Ok(UserInfo {
                username: claims.sub,
            })
        }
        Err(e) => {
            log::warn!("GetUserInfo: verify_token failed: {}", e);
            Err(ServerFnError::new(e))
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserInfo {
    pub username: String,
}
