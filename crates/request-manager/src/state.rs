#[derive(Clone)]
pub struct AppState {
    pub client: reqwest::Client,
    pub eth_rpc_url: String,
}
