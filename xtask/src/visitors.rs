use crate::files::has_cfg_test;
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprMethodCall, ImplItemFn, ItemFn, ItemMod, Macro};

#[derive(Default)]
pub(crate) struct FinalizeVisitor {
    fn_stack: Vec<String>,
    pub(crate) calls: Vec<FinalizeCall>,
}

pub(crate) struct FinalizeCall {
    pub(crate) enclosing_fn: String,
    pub(crate) callee: String,
}

impl FinalizeVisitor {
    fn push_fn<T>(&mut self, name: T)
    where
        T: Into<String>,
    {
        self.fn_stack.push(name.into());
    }

    fn pop_fn(&mut self) {
        self.fn_stack.pop();
    }

    fn current_fn(&self) -> String {
        self.fn_stack
            .last()
            .cloned()
            .unwrap_or_else(|| "<module>".to_string())
    }
}

impl<'ast> Visit<'ast> for FinalizeVisitor {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(path) = node.func.as_ref()
            && let Some(segment) = path.path.segments.last()
        {
            let ident = segment.ident.to_string();
            if ident.starts_with("finalize_response") {
                self.calls.push(FinalizeCall {
                    enclosing_fn: self.current_fn(),
                    callee: ident,
                });
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

#[derive(Default)]
pub(crate) struct UnwrapVisitor {
    fn_stack: Vec<String>,
    pub(crate) panicking_calls: Vec<PanickingMethodCall>,
}

pub(crate) struct PanickingMethodCall {
    pub(crate) enclosing_fn: String,
    pub(crate) method: String,
}

impl UnwrapVisitor {
    fn push_fn<T>(&mut self, name: T)
    where
        T: Into<String>,
    {
        self.fn_stack.push(name.into());
    }

    fn pop_fn(&mut self) {
        self.fn_stack.pop();
    }

    fn current_fn(&self) -> String {
        self.fn_stack
            .last()
            .cloned()
            .unwrap_or_else(|| "<module>".to_string())
    }
}

impl<'ast> Visit<'ast> for UnwrapVisitor {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if has_cfg_test(&node.attrs) || node.attrs.iter().any(|attr| attr.path().is_ident("test")) {
            return;
        }
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if matches!(node.method.to_string().as_str(), "unwrap" | "expect") {
            self.panicking_calls.push(PanickingMethodCall {
                enclosing_fn: self.current_fn(),
                method: node.method.to_string(),
            });
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

pub(crate) struct PanicCall {
    pub(crate) enclosing_fn: String,
    pub(crate) macro_name: String,
}

#[derive(Default)]
pub(crate) struct PanicVisitor {
    fn_stack: Vec<String>,
    pub(crate) panics: Vec<PanicCall>,
}

impl PanicVisitor {
    fn push_fn<T>(&mut self, name: T)
    where
        T: Into<String>,
    {
        self.fn_stack.push(name.into());
    }

    fn pop_fn(&mut self) {
        self.fn_stack.pop();
    }

    fn current_fn(&self) -> String {
        self.fn_stack
            .last()
            .cloned()
            .unwrap_or_else(|| "<module>".to_string())
    }
}

impl<'ast> Visit<'ast> for PanicVisitor {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if has_cfg_test(&node.attrs) || node.attrs.iter().any(|attr| attr.path().is_ident("test")) {
            return;
        }
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if let Some(segment) = node.path.segments.last() {
            let macro_name = segment.ident.to_string();
            if matches!(macro_name.as_str(), "panic" | "todo" | "unimplemented") {
                self.panics.push(PanicCall {
                    enclosing_fn: self.current_fn(),
                    macro_name,
                });
            }
        }
        syn::visit::visit_macro(self, node);
    }
}
