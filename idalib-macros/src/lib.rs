use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Expr, ExprLit, ItemImpl, Lit, LitCStr, Token, parse_macro_input};

const PLUGIN_MOD: i32 = 0x0001;
const PLUGIN_UNL: i32 = 0x0008;
const PLUGIN_FIX: i32 = 0x0080;
const PLUGIN_MULTI: i32 = 0x0100;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum PluginKind {
    #[default]
    Default,
    Resident,
    Oneshot,
}

struct PluginArgs {
    name: String,
    comment: Option<String>,
    help: Option<String>,
    hotkey: Option<String>,
    version: Option<i32>,
    kind: PluginKind,
}

impl Parse for PluginArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut comment = None;
        let mut help = None;
        let mut hotkey = None;
        let mut version = None;
        let mut kind = PluginKind::Default;

        let pairs = Punctuated::<syn::MetaNameValue, Token![,]>::parse_terminated(input)?;
        for pair in pairs {
            let Some(key) = pair.path.get_ident() else {
                return Err(syn::Error::new_spanned(pair.path, "expected identifier"));
            };

            if key == "name" {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) = pair.value
                {
                    name = Some(s.value());
                    continue;
                } else {
                    return Err(syn::Error::new_spanned(
                        pair.value,
                        "expected string literal",
                    ));
                }
            }

            if key == "comment" {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) = pair.value
                {
                    comment = Some(s.value());
                    continue;
                } else {
                    return Err(syn::Error::new_spanned(
                        pair.value,
                        "expected string literal",
                    ));
                }
            }

            if key == "help" {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) = pair.value
                {
                    help = Some(s.value());
                    continue;
                } else {
                    return Err(syn::Error::new_spanned(
                        pair.value,
                        "expected string literal",
                    ));
                }
            }

            if key == "hotkey" {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) = pair.value
                {
                    hotkey = Some(s.value());
                    continue;
                } else {
                    return Err(syn::Error::new_spanned(
                        pair.value,
                        "expected string literal",
                    ));
                }
            }

            if key == "version" {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Int(i), ..
                }) = pair.value
                {
                    version = Some(i.base10_parse()?);
                    continue;
                } else {
                    return Err(syn::Error::new_spanned(
                        pair.value,
                        "expected integer literal",
                    ));
                }
            }

            if key == "kind" {
                if let Expr::Path(ref path) = pair.value
                    && let Some(ident) = path.path.get_ident()
                {
                    kind = if ident == "default" {
                        PluginKind::Default
                    } else if ident == "resident" {
                        PluginKind::Resident
                    } else if ident == "oneshot" {
                        PluginKind::Oneshot
                    } else {
                        return Err(syn::Error::new_spanned(
                            ident,
                            format!(
                                "unknown kind `{ident}`, expected `default`, `resident`, or `oneshot`"
                            ),
                        ));
                    };
                    continue;
                } else {
                    return Err(syn::Error::new_spanned(
                        &pair.value,
                        "expected identifier: `default`, `resident`, or `oneshot`",
                    ));
                }
            }

            return Err(syn::Error::new_spanned(
                &pair.path,
                format!("unknown attribute `{key}`"),
            ));
        }

        Ok(Self {
            name: name.ok_or_else(|| syn::Error::new(input.span(), "missing `name` attribute"))?,
            comment,
            help,
            hotkey,
            version,
            kind,
        })
    }
}

fn make_cstr_literal(s: &str) -> LitCStr {
    let cstring = std::ffi::CString::new(s).expect("string contains null byte");
    LitCStr::new(&cstring, Span::call_site())
}

#[proc_macro_attribute]
pub fn plugin(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as PluginArgs);
    let impl_block = parse_macro_input!(item as ItemImpl);
    let self_ty = &impl_block.self_ty;

    let name = &args.name;
    let name_cstr = make_cstr_literal(name);
    let comment_cstr = make_cstr_literal(args.comment.as_deref().unwrap_or_default());
    let help_cstr = make_cstr_literal(args.help.as_deref().unwrap_or_default());
    let hotkey_cstr = make_cstr_literal(args.hotkey.as_deref().unwrap_or_default());

    let base_flags = PLUGIN_MULTI | PLUGIN_MOD;
    let kind_flag = match args.kind {
        PluginKind::Default => 0,
        PluginKind::Resident => PLUGIN_FIX,
        PluginKind::Oneshot => PLUGIN_UNL,
    };
    let computed_flags = base_flags | kind_flag;
    let version = args.version.unwrap_or(900);

    let expanded = quote! {
        #impl_block

        extern "C" fn __idalib_plugin_init() -> *mut idalib::ffi::plugin::plugmod_t {
            let mut idb = match idalib::IDB::current() {
                Ok(idb) => idb,
                Err(e) => {
                    let _ = unsafe {
                        idalib::ffi::ida::msg(&format!("[{}] plugin initialisation failed: {e}\n", #name))
                    };
                    return ::std::ptr::null_mut();
                }
            };

            let mut ida = idalib::IDA::new(&idb);

            match <#self_ty as idalib::plugin::IDAPlugin>::init(&mut ida, &mut idb) {
                Ok(plugin) => {
                    let wrapper = idalib::plugin::PlugmodWrapper::new(#name, plugin);
                    let plugmod = Box::new(idalib::ffi::plugin::PlugMod::new(wrapper));
                    unsafe { idalib::ffi::plugin::idalib_create_plugmod(plugmod) }
                }
                Err(e) => {
                    ida.msg(&format!("[{}] plugin initialisation failed: {e}\n", #name)).ok();
                    ::std::ptr::null_mut()
                }
            }
        }

        #[unsafe(no_mangle)]
        pub static mut PLUGIN: idalib::ffi::plugin::plugin_t = idalib::ffi::plugin::plugin_t {
            version: #version,
            flags: #computed_flags,
            init: Some(__idalib_plugin_init),
            term: None,
            run: None,
            comment: #comment_cstr.as_ptr(),
            help: #help_cstr.as_ptr(),
            wanted_name: #name_cstr.as_ptr(),
            wanted_hotkey: #hotkey_cstr.as_ptr(),
        };
    };

    expanded.into()
}
