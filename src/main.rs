use p2p_handshake::{
    app::{get_node_info, handshake},
    error::{Error, Result},
};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenvy::dotenv().ok();
    env_logger::init();

    let (node_public_key, node_address) = get_node_info()?;
    let mut stream = TcpStream::connect(&node_address).await?;
    handshake(&mut stream, node_public_key).await?;

    Ok(())
}
