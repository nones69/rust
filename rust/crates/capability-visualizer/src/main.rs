mod render;
mod tree;

use render::render_tree;
use tree::build_tree;

use clap::Parser;
use intentos_kernel::verify_token;
use uuid::Uuid;

const DEFAULT_TOKEN: &str = "11111111-2222-3333-4444-555555555555";

#[derive(Parser)]
#[command(name = "capability-visualizer", about = "Visualize an IntentOS capability token as an ASCII tree")]
struct Args {
    /// Token UUID to inspect (defaults to the built-in demo token)
    #[arg(long, default_value = DEFAULT_TOKEN)]
    token: Uuid,
}

fn main() {
    println!("Capability Visualizer");
    println!();

    let args = Args::parse();

    let token = verify_token(&args.token).expect("token not found");

    let tree = build_tree(&token);
    println!("{}", tree.label);
    for (i, child) in tree.children.iter().enumerate() {
        render_tree(child, "", i == tree.children.len() - 1);
    }
}
