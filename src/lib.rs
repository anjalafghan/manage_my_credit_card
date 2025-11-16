use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::{components::*, *};

#[cfg(feature = "ssr")]
pub mod auth;
#[cfg(feature = "ssr")]
pub mod db;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}

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
                Ok(_token) => {
                    #[cfg(not(feature = "ssr"))]
                    {
                        use leptos::web_sys;
                        leptos::logging::log!("Login successful, storing token");
                        let window = web_sys::window().unwrap();
                        let storage = window.local_storage().unwrap().unwrap();
                        let _ = storage.set_item("token", &_token);

                        let location = window.location();
                        let _ = location.set_href("/dashboard");
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
                        use leptos::web_sys;
                        leptos::logging::log!("Registration successful, redirecting to login");
                        let window = web_sys::window().unwrap();
                        let location = window.location();
                        let _ = location.set_href("/login");
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

#[component]
fn DashboardPage() -> impl IntoView {
    use leptos::prelude::*;

    let (username, set_username) = signal(None::<String>);
    let (error, set_error) = signal(None::<String>);

    // --- existing spawn_local code stays the same ---

    #[cfg(not(feature = "ssr"))]
    {
        use leptos::logging::log;
        use leptos::web_sys;

        let set_username_cloned = set_username.clone();
        let set_error_cloned = set_error.clone();

        leptos::task::spawn_local(async move {
            log!("Dashboard: starting client-side user info fetch");

            let token = {
                let window = match web_sys::window() {
                    Some(w) => w,
                    None => {
                        set_error_cloned.set(Some("No window object".to_string()));
                        log!("Dashboard: No window object");
                        return;
                    }
                };

                let storage = match window.local_storage() {
                    Ok(Some(s)) => s,
                    Ok(None) => {
                        set_error_cloned.set(Some("localStorage not available".to_string()));
                        log!("Dashboard: localStorage not available");
                        return;
                    }
                    Err(_) => {
                        set_error_cloned.set(Some("Error accessing localStorage".to_string()));
                        log!("Dashboard: error accessing localStorage");
                        return;
                    }
                };

                match storage.get_item("token") {
                    Ok(Some(t)) => {
                        log!("Dashboard: token read from localStorage, len={}", t.len());
                        t
                    }
                    Ok(None) => {
                        set_error_cloned.set(Some("No token in localStorage".to_string()));
                        log!("Dashboard: no token in localStorage");
                        return;
                    }
                    Err(_) => {
                        set_error_cloned
                            .set(Some("Failed to read token from localStorage".to_string()));
                        log!("Dashboard: failed to read token");
                        return;
                    }
                }
            };

            match get_user_info(token).await {
                Ok(info) => {
                    log!("Dashboard: get_user_info OK for user {}", info.username);
                    set_username_cloned.set(Some(info.username));
                }
                Err(e) => {
                    log!("Dashboard: get_user_info ERROR: {:?}", e);
                    set_error_cloned.set(Some(format!("{e}")));
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
                                <p class="debug">"Debug: Dashboard loaded successfully."</p>
                                <button on:click={
                                    let set_username = set_username.clone();
                                    let set_error = set_error.clone();
                                    move |_| {
                                        #[cfg(not(feature = "ssr"))]
                                        {
                                            use leptos::logging::log;
                                            use leptos::web_sys;

                                            log!("Dashboard: logout clicked, removing token & redirecting.");
                                            if let Some(window) = web_sys::window() {
                                                if let Ok(Some(storage)) = window.local_storage() {
                                                    let _ = storage.remove_item("token");
                                                }
                                                // update local state (so if redirect fails, UI still reflects logout)
                                                set_username.set(None);
                                                set_error.set(Some("You have been logged out.".to_string()));

                                                // redirect to login
                                                let _ = window.location().set_href("/login");
                                            }
                                        }
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
                                <p class="debug">
                                    "Debug: you can manually go to /login to log in again."
                                </p>
                            </div>
                        }.into_any()
                    } else {
                        // ⏳ Loading state
                        view! {
                            <p>"Loading user info..."</p>
                        }.into_any()
                    }
                }}
            </div>
        </div>
    }
}

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

#[cfg(not(feature = "ssr"))]
pub fn logout() {
    use leptos::logging::log;
    use leptos::web_sys;

    log!("Auth: logout called, removing token and redirecting to /login");

    if let Some(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            let _ = storage.remove_item("token");
        }

        // Redirect to login page
        let _ = window.location().set_href("/login");
    }
}

#[cfg(feature = "ssr")]
pub fn logout() {
    // No-op on server
}
