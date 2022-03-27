use rand::prelude::SliceRandom;
use rand::rngs::OsRng;
use syn::visit::*;
use syn::visit_mut::*;
use syn::*;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

struct ExprShuffle {
    list: Vec<Expr>,
}

//TODO: Need scoping, separate shuffle regions, as well as function boundaries
//We don't want to have shuffle being global across a file
impl ExprShuffle {
    fn is_shuffle_attr(attr: &str) -> bool {
        match attr {
            "shufflecase" => true,
            _ => false,
        }
    }
    fn get_attr_name(attr: &Attribute) -> String {
        if let Some(ident) = attr.path.get_ident() {
            ident.to_string()
        } else {
            "".to_string()
        }
    }
    fn contains_shuffle_attr(attrs: &Vec<Attribute>) -> bool {
        for attr in attrs {
            if ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr)) {
                return true;
            }
        }
        return false;
    }

    //TODO: I hate this much code duplication, but I don't have a better idea yet
    fn fetch_shuffled_statements(&mut self, node: &Expr) {
        match node {
            Expr::Array(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Assign(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::AssignOp(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Async(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Await(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Binary(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Block(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Box(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Break(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Call(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Cast(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Closure(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Continue(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Field(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::ForLoop(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Group(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::If(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Index(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Let(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Lit(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Loop(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Macro(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Match(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::MethodCall(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Paren(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Path(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Range(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Reference(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Repeat(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Return(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Struct(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Try(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::TryBlock(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Tuple(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Type(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Unary(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Unsafe(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::While(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            Expr::Yield(expr) => {
                let mut dup_node = expr.clone();
                if ExprShuffle::contains_shuffle_attr(&dup_node.attrs) {
                    dup_node.attrs = dup_node
                        .attrs
                        .iter()
                        .map(|attr| attr.to_owned())
                        .filter(|attr| {
                            !ExprShuffle::is_shuffle_attr(&ExprShuffle::get_attr_name(&attr))
                        })
                        .collect();
                    self.list.push(syn::Expr::from(dup_node));
                }
            }
            _ => {}
        };
    }
    fn replace_shuffle_case(&mut self, attrs: &Vec<Attribute>, node: &Expr) -> Expr {
        if ExprShuffle::contains_shuffle_attr(attrs) && !self.list.is_empty() {
            //TODO: This statement doesn't remove the attribute when I add a shufflecase attribute
            //to it
            //Might need to use Stmt to enforce Semicolon termination at the top level
            //Best guess is that multiple Expressions are getting tripped up
            let selection = self.list.first().unwrap().clone();
            self.list.remove(0);
            return selection;
        }
        node.clone()
    }
}

impl Visit<'_> for ExprShuffle {
    fn visit_expr(&mut self, node: &Expr) {
        self.fetch_shuffled_statements(node);
        // Delegate to the default impl to visit nested expressions.
        visit::visit_expr(self, node);
    }
}
impl VisitMut for ExprShuffle {
    fn visit_expr_mut(&mut self, node: &mut Expr) {
        let new_node = match &*node {
            Expr::Array(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Assign(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::AssignOp(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Async(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Await(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Binary(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Block(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Box(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Break(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Call(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Cast(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Closure(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Continue(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Field(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::ForLoop(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Group(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::If(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Index(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Let(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Lit(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Loop(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Macro(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Match(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::MethodCall(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Paren(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Path(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Range(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Reference(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Repeat(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Return(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Struct(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Try(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::TryBlock(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Tuple(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Type(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Unary(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Unsafe(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::While(expr) => self.replace_shuffle_case(&expr.attrs, node),
            Expr::Yield(expr) => self.replace_shuffle_case(&expr.attrs, node),
            _ => node.to_owned(),
        };
        *node = new_node;
        // Delegate to the default impl to visit nested expressions.
        visit_mut::visit_expr_mut(self, node);
    }
}

pub fn shuffle(input: &mut File) {
    let mut shuf = ExprShuffle { list: vec![] };
    ExprShuffle::visit_file(&mut shuf, input);
    shuf.list.shuffle(&mut OsRng);
    ExprShuffle::visit_file_mut(&mut shuf, input);
}
