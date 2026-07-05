use intentos_kernel::{AiScope, FsScope, NetScope, TokenScope};
use intentos_kernel::VerifiedToken;

use crate::render::TreeNode;

/// Build a `TreeNode` tree representing all fields in `token`.
pub fn build_tree(token: &VerifiedToken) -> TreeNode {
    let mut root = TreeNode::new(format!("Token {}", token.id));

    root.add_child(TreeNode::new(format!("Issued To: {}", token.issued_to)));

    let expires = token
        .expires_at
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| {
            let secs = d.as_secs();
            format!("{}s since epoch", secs)
        })
        .unwrap_or_else(|_| "unknown".to_string());
    root.add_child(TreeNode::new(format!("Expires At: {}", expires)));

    root.add_child(quota_to_tree(token));

    let scope_node = scope_to_tree(&token.scope);
    root.add_child(scope_node);

    root
}

fn quota_to_tree(token: &VerifiedToken) -> TreeNode {
    let q = &token.quota;
    let mut node = TreeNode::new("Quota");
    node.add_child(TreeNode::new(format!("max_bytes: {:?}", q.max_bytes)));
    node.add_child(TreeNode::new(format!("bytes_used: {}", q.bytes_used)));
    node.add_child(TreeNode::new(format!("max_requests: {:?}", q.max_requests)));
    node.add_child(TreeNode::new(format!("requests_used: {}", q.requests_used)));
    node.add_child(TreeNode::new(format!("ttl_ms: {:?}", q.ttl_ms)));
    node
}

fn scope_to_tree(scope: &TokenScope) -> TreeNode {
    match scope {
        TokenScope::Fs(fs) => fs_to_tree(fs),
        TokenScope::Net(net) => net_to_tree(net),
        TokenScope::Ai(ai) => ai_to_tree(ai),
        TokenScope::Composite(list) => {
            let mut node = TreeNode::new("Composite Scope");
            for s in list {
                node.add_child(scope_to_tree(s));
            }
            node
        }
    }
}

fn fs_to_tree(fs: &FsScope) -> TreeNode {
    let mut node = TreeNode::new("FsScope");
    node.add_child(TreeNode::new(format!("path_prefix: {}", fs.path_prefix)));
    node.add_child(TreeNode::new(format!("ops: {:?}", fs.ops)));
    node
}

fn net_to_tree(net: &NetScope) -> TreeNode {
    let mut node = TreeNode::new("NetScope");
    node.add_child(TreeNode::new(format!("hosts: {:?}", net.hosts)));
    node.add_child(TreeNode::new(format!("methods: {:?}", net.methods)));
    node
}

fn ai_to_tree(ai: &AiScope) -> TreeNode {
    let mut node = TreeNode::new("AiScope");
    node.add_child(TreeNode::new(format!("model: {}", ai.model)));
    node.add_child(TreeNode::new(format!("max_tokens: {:?}", ai.max_tokens)));
    node
}
