mod render;
mod tree;

use render::render_tree;
use tree::build_tree;

use intentos_kernel::verify_token;
use uuid::Uuid;

fn main() {
    println!("Capability Visualizer");
    println!();

    let token_id = Uuid::parse_str("11111111-2222-3333-4444-555555555555")
        .expect("invalid token UUID");

    let token = verify_token(&token_id).expect("token not found");

    let tree = build_tree(&token);
    // Print root label first, then render its children with the standard connector
    println!("{}", tree.label);
    for (i, child) in tree.children.iter().enumerate() {
        render_tree(child, "", i == tree.children.len() - 1);
    }
}
