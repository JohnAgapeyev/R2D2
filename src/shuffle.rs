use rand::prelude::SliceRandom;
use rand::rngs::OsRng;
use syn::spanned::Spanned;
use syn::visit_mut::*;
use syn::*;

//Workaround to self obfuscate (since we can't add ourselves as a dependency)
#[allow(unused_imports)]
use crate as r2d2;

const SHUFFLE_ATTR_NAME: &str = "shuffle";

trait HasAttributes {
    fn get_attrs(&mut self) -> Option<&mut Vec<Attribute>>;
    fn to_stmt(self) -> Stmt;
}

impl HasAttributes for Expr {
    fn get_attrs(&mut self) -> Option<&mut Vec<Attribute>> {
        match self {
            Expr::Array(expr) => Some(&mut expr.attrs),
            Expr::Assign(expr) => Some(&mut expr.attrs),
            Expr::AssignOp(expr) => Some(&mut expr.attrs),
            Expr::Async(expr) => Some(&mut expr.attrs),
            Expr::Await(expr) => Some(&mut expr.attrs),
            Expr::Binary(expr) => Some(&mut expr.attrs),
            Expr::Block(expr) => Some(&mut expr.attrs),
            Expr::Box(expr) => Some(&mut expr.attrs),
            Expr::Break(expr) => Some(&mut expr.attrs),
            Expr::Call(expr) => Some(&mut expr.attrs),
            Expr::Cast(expr) => Some(&mut expr.attrs),
            Expr::Closure(expr) => Some(&mut expr.attrs),
            Expr::Continue(expr) => Some(&mut expr.attrs),
            Expr::Field(expr) => Some(&mut expr.attrs),
            Expr::ForLoop(expr) => Some(&mut expr.attrs),
            Expr::Group(expr) => Some(&mut expr.attrs),
            Expr::If(expr) => Some(&mut expr.attrs),
            Expr::Index(expr) => Some(&mut expr.attrs),
            Expr::Let(expr) => Some(&mut expr.attrs),
            Expr::Lit(expr) => Some(&mut expr.attrs),
            Expr::Loop(expr) => Some(&mut expr.attrs),
            Expr::Macro(expr) => Some(&mut expr.attrs),
            Expr::Match(expr) => Some(&mut expr.attrs),
            Expr::MethodCall(expr) => Some(&mut expr.attrs),
            Expr::Paren(expr) => Some(&mut expr.attrs),
            Expr::Path(expr) => Some(&mut expr.attrs),
            Expr::Range(expr) => Some(&mut expr.attrs),
            Expr::Reference(expr) => Some(&mut expr.attrs),
            Expr::Repeat(expr) => Some(&mut expr.attrs),
            Expr::Return(expr) => Some(&mut expr.attrs),
            Expr::Struct(expr) => Some(&mut expr.attrs),
            Expr::Try(expr) => Some(&mut expr.attrs),
            Expr::TryBlock(expr) => Some(&mut expr.attrs),
            Expr::Tuple(expr) => Some(&mut expr.attrs),
            Expr::Type(expr) => Some(&mut expr.attrs),
            Expr::Unary(expr) => Some(&mut expr.attrs),
            Expr::Unsafe(expr) => Some(&mut expr.attrs),
            Expr::While(expr) => Some(&mut expr.attrs),
            Expr::Yield(expr) => Some(&mut expr.attrs),
            _ => None,
        }
    }

    fn to_stmt(self) -> Stmt {
        let semi = Token![;](self.span());
        Stmt::Semi(self, semi)
    }
}

impl HasAttributes for Local {
    fn get_attrs(&mut self) -> Option<&mut Vec<Attribute>> {
        Some(&mut self.attrs)
    }
    fn to_stmt(self) -> Stmt {
        Stmt::Local(self)
    }
}

impl HasAttributes for Item {
    fn get_attrs(&mut self) -> Option<&mut Vec<Attribute>> {
        match self {
            Item::Const(item) => Some(&mut item.attrs),
            Item::Enum(item) => Some(&mut item.attrs),
            Item::ExternCrate(item) => Some(&mut item.attrs),
            Item::Fn(item) => Some(&mut item.attrs),
            Item::ForeignMod(item) => Some(&mut item.attrs),
            Item::Impl(item) => Some(&mut item.attrs),
            Item::Macro(item) => Some(&mut item.attrs),
            Item::Macro2(item) => Some(&mut item.attrs),
            Item::Mod(item) => Some(&mut item.attrs),
            Item::Static(item) => Some(&mut item.attrs),
            Item::Struct(item) => Some(&mut item.attrs),
            Item::Trait(item) => Some(&mut item.attrs),
            Item::TraitAlias(item) => Some(&mut item.attrs),
            Item::Type(item) => Some(&mut item.attrs),
            Item::Union(item) => Some(&mut item.attrs),
            Item::Use(item) => Some(&mut item.attrs),
            _ => None,
        }
    }
    fn to_stmt(self) -> Stmt {
        Stmt::Item(self)
    }
}

impl HasAttributes for Stmt {
    fn get_attrs(&mut self) -> Option<&mut Vec<Attribute>> {
        match self {
            Stmt::Local(local) => local.get_attrs(),
            Stmt::Item(item) => item.get_attrs(),
            //Ignore Expr, we only want to shuffle statements with semicolons
            Stmt::Semi(expr, _semi) => expr.get_attrs(),
            _ => None,
        }
    }
    fn to_stmt(self) -> Stmt {
        self
    }
}

fn is_shuffle_attr(attr: &str) -> bool {
    match attr {
        SHUFFLE_ATTR_NAME => true,
        _ => false,
    }
}

fn get_attr_name(attr: &Attribute) -> String {
    attr.path
        .get_ident()
        .map_or(String::new(), |ident| ident.to_string())
}

fn contains_shuffle_attr(attrs: &Vec<Attribute>) -> bool {
    for attr in attrs {
        if is_shuffle_attr(&get_attr_name(&attr)) {
            return true;
        }
    }
    return false;
}

//TODO: This and the shuffle finding are inefficient, try and remove all the cloning
fn stmt_contains_shuffle_attr(stmt: &Stmt) -> bool {
    let mut cloned = stmt.to_owned();
    let cloned_attrs = cloned.get_attrs();
    if cloned_attrs.is_none() {
        return false;
    }
    let cloned_attrs_ref = cloned_attrs.unwrap();
    contains_shuffle_attr(cloned_attrs_ref)
}

fn find_shuffle_stmts<T>(expr: &T) -> Option<Stmt>
where
    T: HasAttributes + ToOwned<Owned = T>,
{
    let mut cloned = expr.to_owned();
    let cloned_attrs = cloned.get_attrs();
    if cloned_attrs.is_none() {
        return None;
    }
    let cloned_attrs_ref = cloned_attrs.unwrap();
    if contains_shuffle_attr(&cloned_attrs_ref) {
        //Remove the shuffle attribute from the cloned target statement
        let stripped_attrs: Vec<Attribute> = cloned_attrs_ref
            .iter()
            .filter(|attr| !is_shuffle_attr(&get_attr_name(attr)))
            .map(|attr| attr.to_owned())
            .collect();
        *cloned_attrs_ref = stripped_attrs;
        return Some(cloned.to_stmt());
    }
    return None;
}

struct Shuffle;

impl VisitMut for Shuffle {
    fn visit_block_mut(&mut self, block: &mut Block) {
        let mut targets: Vec<Stmt> = Vec::new();
        for stmt in &block.stmts {
            let result = match stmt {
                Stmt::Local(local) => find_shuffle_stmts::<Local>(local),
                Stmt::Item(item) => find_shuffle_stmts::<Item>(item),
                //Ignore Expr, we only want to shuffle statements with semicolons
                Stmt::Semi(expr, _semi) => find_shuffle_stmts::<Expr>(expr),
                _ => None,
            };
            if result.is_some() {
                targets.push(result.unwrap());
            }
        }
        targets.shuffle(&mut OsRng);
        for stmt in &mut block.stmts {
            if stmt_contains_shuffle_attr(stmt) {
                let replacement = targets.pop().unwrap();
                *stmt = replacement;
            }
            // Delegate to the default impl to visit nested scopes.
            Self::visit_stmt_mut(self, stmt);
        }
    }
}

pub fn shuffle(input: &mut File) {
    Shuffle.visit_file_mut(input);
}
