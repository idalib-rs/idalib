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
    flags: Option<Expr>,
    version: Option<i32>,
    kind: PluginKind,
}

fn validate_flags_expr(expr: &Expr) -> syn::Result<()> {
    let tokens = quote!(#expr).to_string();

    let forbidden = [
        (
            "MULTI",
            "MULTI is always set automatically; remove from flags",
        ),
        ("MOD", "MOD is always set automatically; remove from flags"),
        ("FIX", "use `kind = resident` instead of flags for FIX"),
        ("UNL", "use `kind = oneshot` instead of flags for UNL"),
    ];

    for (flag, message) in forbidden {
        if tokens.contains(flag) {
            return Err(syn::Error::new_spanned(expr, message));
        }
    }

    Ok(())
}

impl Parse for PluginArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut comment = None;
        let mut help = None;
        let mut hotkey = None;
        let mut flags = None;
        let mut version = None;
        let mut kind = PluginKind::Default;

        let pairs = Punctuated::<syn::MetaNameValue, Token![,]>::parse_terminated(input)?;
        for pair in pairs {
            let key = pair.path.get_ident().map(|i| i.to_string());
            match key.as_deref() {
                Some("name") => {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Str(s), ..
                    }) = pair.value
                    {
                        name = Some(s.value());
                    } else {
                        return Err(syn::Error::new_spanned(
                            pair.value,
                            "expected string literal",
                        ));
                    }
                }
                Some("comment") => {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Str(s), ..
                    }) = pair.value
                    {
                        comment = Some(s.value());
                    } else {
                        return Err(syn::Error::new_spanned(
                            pair.value,
                            "expected string literal",
                        ));
                    }
                }
                Some("help") => {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Str(s), ..
                    }) = pair.value
                    {
                        help = Some(s.value());
                    } else {
                        return Err(syn::Error::new_spanned(
                            pair.value,
                            "expected string literal",
                        ));
                    }
                }
                Some("hotkey") => {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Str(s), ..
                    }) = pair.value
                    {
                        hotkey = Some(s.value());
                    } else {
                        return Err(syn::Error::new_spanned(
                            pair.value,
                            "expected string literal",
                        ));
                    }
                }
                Some("flags") => {
                    validate_flags_expr(&pair.value)?;
                    flags = Some(pair.value);
                }
                Some("version") => {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Int(i), ..
                    }) = pair.value
                    {
                        version = Some(i.base10_parse()?);
                    } else {
                        return Err(syn::Error::new_spanned(
                            pair.value,
                            "expected integer literal",
                        ));
                    }
                }
                Some("kind") => {
                    if let Expr::Path(ref path) = pair.value {
                        if let Some(ident) = path.path.get_ident() {
                            match ident.to_string().as_str() {
                                "default" => kind = PluginKind::Default,
                                "resident" => kind = PluginKind::Resident,
                                "oneshot" => kind = PluginKind::Oneshot,
                                other => {
                                    return Err(syn::Error::new_spanned(
                                        ident,
                                        format!(
                                            "unknown kind `{other}`, expected `default`, `resident`, or `oneshot`"
                                        ),
                                    ));
                                }
                            }
                        } else {
                            return Err(syn::Error::new_spanned(
                                &pair.value,
                                "expected identifier: `default`, `resident`, or `oneshot`",
                            ));
                        }
                    } else {
                        return Err(syn::Error::new_spanned(
                            &pair.value,
                            "expected identifier: `default`, `resident`, or `oneshot`",
                        ));
                    }
                }
                Some(other) => {
                    return Err(syn::Error::new_spanned(
                        pair.path,
                        format!("unknown attribute `{other}`"),
                    ));
                }
                None => {
                    return Err(syn::Error::new_spanned(pair.path, "expected identifier"));
                }
            }
        }

        Ok(Self {
            name: name.ok_or_else(|| syn::Error::new(input.span(), "missing `name` attribute"))?,
            comment,
            help,
            hotkey,
            flags,
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

    let flags_expr = match args.flags {
        Some(f) => quote! { #computed_flags | (#f).bits() as i32 },
        None => quote! { #computed_flags },
    };
    let version = args.version.unwrap_or(900);

    let expanded = quote! {
        #impl_block

        extern "C" fn __idalib_plugin_init() -> *mut idalib::ffi::plugin::plugmod_t {
            let mut idb = match idalib::IDB::current() {
                Ok(idb) => idb,
                Err(e) => {
                    let _ = unsafe { idalib::ffi::ida::msg(&format!("[{}] `init` failed: {e}\n", #name)) };
                    return ::std::ptr::null_mut();
                }
            };

            match <#self_ty as idalib::plugin::IDAPlugin>::init(&mut idb) {
                Ok(plugin) => {
                    let wrapper = idalib::plugin::PlugmodWrapper::new(#name, plugin);
                    let plugmod = Box::new(idalib::ffi::plugin::PlugMod::new(wrapper));
                    unsafe { idalib::ffi::plugin::idalib_create_plugmod(plugmod) }
                }
                Err(e) => {
                    let _ = unsafe { idalib::ffi::ida::msg(&format!("[{}] `init` failed: {e}\n", #name)) };
                    ::std::ptr::null_mut()
                }
            }
        }

        #[unsafe(no_mangle)]
        pub static mut PLUGIN: idalib::ffi::plugin::plugin_t = idalib::ffi::plugin::plugin_t {
            version: #version,
            flags: #flags_expr,
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
