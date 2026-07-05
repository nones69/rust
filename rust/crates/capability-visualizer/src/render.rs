/// A node in the capability tree.
#[derive(Debug)]
pub struct TreeNode {
    pub label: String,
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            children: vec![],
        }
    }

    pub fn add_child(&mut self, child: TreeNode) {
        self.children.push(child);
    }
}

/// Render a tree node to stdout using ASCII box-drawing characters.
/// Call with `prefix = ""` and `last = true` for the root node.
pub fn render_tree(node: &TreeNode, prefix: &str, last: bool) {
    let connector = if last { "└── " } else { "├── " };
    println!("{}{}{}", prefix, connector, node.label);

    let new_prefix = if last {
        format!("{}    ", prefix)
    } else {
        format!("{}│   ", prefix)
    };

    for (i, child) in node.children.iter().enumerate() {
        render_tree(child, &new_prefix, i == node.children.len() - 1);
    }
}
