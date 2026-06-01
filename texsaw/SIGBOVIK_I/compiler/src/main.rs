use std::{
    collections::{HashMap, HashSet},
    io::{Read, stdin},
};

#[derive(Debug)]
enum Token<'a> {
    Int(u64),
    Bool(bool),
    Char(u8),
    Symbol(&'a [u8]),
    Null,
    Form(Vec<Token<'a>>),
    String(Vec<u8>),
    Dot,
}

struct Primitive<'a> {
    mnemonic: &'a str,
    minimum_arity: usize,
    is_variadic: bool,
}

impl Primitive<'_> {
    #[allow(clippy::too_many_lines)]
    fn from_bytes(input: &[u8]) -> Option<Primitive<'_>> {
        match input {
            b"zero?" => Some(Primitive {
                mnemonic: "ZEROP",
                minimum_arity: 1,
                is_variadic: false,
            }),
            b"integer?" => Some(Primitive {
                mnemonic: "INTEGERP",
                minimum_arity: 1,
                is_variadic: false,
            }),
            b"boolean?" => Some(Primitive {
                mnemonic: "BOOLEANP",
                minimum_arity: 1,
                is_variadic: false,
            }),
            b"char?" => Some(Primitive {
                mnemonic: "CHARP",
                minimum_arity: 1,
                is_variadic: false,
            }),
            b"null?" => Some(Primitive {
                mnemonic: "NULLP",
                minimum_arity: 1,
                is_variadic: false,
            }),
            b"not" => Some(Primitive {
                mnemonic: "NOT",
                minimum_arity: 1,
                is_variadic: false,
            }),
            b"char->integer" => Some(Primitive {
                mnemonic: "CHARTOINT",
                minimum_arity: 1,
                is_variadic: false,
            }),
            b"integer->char" => Some(Primitive {
                mnemonic: "INTTOCHAR",
                minimum_arity: 1,
                is_variadic: false,
            }),
            b"+" => Some(Primitive {
                mnemonic: "ADD",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"-" => Some(Primitive {
                mnemonic: "SUB",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"*" => Some(Primitive {
                mnemonic: "MUL",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"<" => Some(Primitive {
                mnemonic: "LT",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"=" => Some(Primitive {
                mnemonic: "EQ",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"eq?" => Some(Primitive {
                mnemonic: "EQP",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"string" => Some(Primitive {
                mnemonic: "STRING",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"string-append" => Some(Primitive {
                mnemonic: "STRINGAPPEND",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"string-ref" => Some(Primitive {
                mnemonic: "STRINGREF",
                minimum_arity: 2,
                is_variadic: false,
            }),
            b"string-set!" => Some(Primitive {
                mnemonic: "STRINGSET",
                minimum_arity: 3,
                is_variadic: false,
            }),
            b"vector" => Some(Primitive {
                mnemonic: "VECTOR",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"vector-append" => Some(Primitive {
                mnemonic: "VECTORAPPEND",
                minimum_arity: 0,
                is_variadic: true,
            }),
            b"vector-ref" => Some(Primitive {
                mnemonic: "VECTORREF",
                minimum_arity: 2,
                is_variadic: false,
            }),
            b"vector-set!" => Some(Primitive {
                mnemonic: "VECTORSET",
                minimum_arity: 3,
                is_variadic: false,
            }),
            b"cons" => Some(Primitive {
                mnemonic: "CONS",
                minimum_arity: 2,
                is_variadic: false,
            }),
            b"car" => Some(Primitive {
                mnemonic: "CAR",
                minimum_arity: 1,
                is_variadic: false,
            }),
            b"cdr" => Some(Primitive {
                mnemonic: "CDR",
                minimum_arity: 1,
                is_variadic: false,
            }),
            _ => None,
        }
    }
}

fn is_delimiter(v: u8) -> bool {
    v.is_ascii_whitespace() || matches!(v, b'(' | b')' | b';')
}

fn starts_with_delimiter(input: &[u8]) -> bool {
    input.is_empty() || is_delimiter(input[0])
}

fn is_symbol_start_char(v: u8) -> bool {
    v.is_ascii_alphabetic()
        || v.is_ascii_digit()
        || matches!(
            v,
            b'-' | b'+'
                | b'='
                | b'_'
                | b'*'
                | b'&'
                | b'^'
                | b'%'
                | b'$'
                | b'!'
                | b'~'
                | b':'
                | b'|'
                | b'\\'
                | b'?'
                | b'/'
                | b'<'
                | b'>'
        )
}

fn negate_62(v: u64) -> u64 {
    (!v).wrapping_add(1) & !(0b11 << 62)
}

fn is_symbol_char(v: u8) -> bool {
    is_symbol_start_char(v) || v == b'#'
}

fn consume_string_literal(input: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    if let Some(mut input) = consume_bytes(input, b"\"") {
        let mut result = Vec::new();
        loop {
            if let Some(new_input) = consume_bytes(input, b"\\\\") {
                result.push(b'\\');
                input = new_input;
            } else if let Some(new_input) = consume_bytes(input, b"\\n") {
                result.push(b'\n');
                input = new_input;
            } else if let Some(new_input) = consume_bytes(input, b"\\t") {
                result.push(b'\t');
                input = new_input;
            } else if let Some(new_input) = consume_bytes(input, b"\\\"") {
                result.push(b'"');
                input = new_input;
            } else if let Some(new_input) = consume_bytes(input, b"\\") {
                result.push(b'\n');
                input = new_input;
            } else if let Some(new_input) = consume_bytes(input, b"\"") {
                input = new_input;
                break;
            } else if input.starts_with(b"\\") {
                panic!("Unrecognized escape sequence in string literal!");
            } else {
                result.push(input[0]);
                input = &input[1..];
            }
        }
        Some((result, input))
    } else {
        None
    }
}

fn consume_symbol(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.is_empty() || !is_symbol_start_char(input[0]) {
        return None;
    }

    let mut bytes_consumed: usize = 1;
    while bytes_consumed < input.len() && is_symbol_char(input[bytes_consumed]) {
        bytes_consumed += 1;
    }

    let (symbol, input) = input.split_at(bytes_consumed);
    if starts_with_delimiter(input) && symbol.iter().any(|c| !c.is_ascii_digit()) {
        Some((symbol, input))
    } else {
        None
    }
}

fn consume_character(input: &[u8]) -> Option<(u8, &[u8])> {
    if let Some(input) = consume_bytes(input, b"#\\")
        && !input.is_empty()
        && starts_with_delimiter(&input[1..])
    {
        Some((input[0], &input[1..]))
    } else {
        None
    }
}

fn consume_null(input: &[u8]) -> Option<&[u8]> {
    if let Some(input) = consume_bytes(input, b"'")
        && let Some(input) = consume_bytes(consume_whitespace(input), b"(")
        && let Some(input) = consume_bytes(consume_whitespace(input), b")")
    {
        Some(input)
    } else {
        None
    }
}

fn consume_dot(input: &[u8]) -> Option<&[u8]> {
    if let Some(input) = consume_bytes(input, b".") {
        Some(input)
    } else {
        None
    }
}

fn consume_form(input: &[u8]) -> Option<(Vec<Token<'_>>, &[u8])> {
    if let Some(input) = consume_bytes(input, b"(") {
        let (args, input) = consume_expressions(consume_whitespace(input));
        if let Some(input) = consume_bytes(consume_whitespace(input), b")") {
            Some((args, input))
        } else {
            None
        }
    } else {
        None
    }
}

fn consume_bytes<'a>(input: &'a [u8], pattern: &'a [u8]) -> Option<&'a [u8]> {
    if input.starts_with(pattern) {
        Some(&input[pattern.len()..])
    } else {
        None
    }
}

fn consume_int(input: &[u8]) -> Option<(u64, &[u8])> {
    let mut result: u64 = 0;
    let mut bytes_consumed: usize = 0;
    let mut is_negated = false;
    if !input.is_empty() && input[0] == b'-' {
        is_negated = true;
        bytes_consumed = 1;
    }
    while bytes_consumed < input.len() && input[bytes_consumed].is_ascii_digit() {
        result *= 10;
        result += u64::from(input[bytes_consumed] - b'0');
        bytes_consumed += 1;
    }
    if bytes_consumed == 0 || (is_negated && bytes_consumed == 1) {
        return None;
    }
    let input = &input[bytes_consumed..];
    if starts_with_delimiter(input) {
        Some((
            if is_negated {
                negate_62(result)
            } else {
                result
            },
            input,
        ))
    } else {
        None
    }
}

fn consume_bool(input: &[u8]) -> Option<(bool, &[u8])> {
    const BOOL_LITERAL_LEN: usize = 2;
    let result = match input {
        [b'#', b't' | b'T', ..] => true,
        [b'#', b'f' | b'F', ..] => false,
        _ => {
            return None;
        }
    };
    let input = &input[BOOL_LITERAL_LEN..];
    if starts_with_delimiter(input) {
        Some((result, input))
    } else {
        None
    }
}

fn consume_line_comment(input: &[u8]) -> Option<&[u8]> {
    if let Some(mut input) = consume_bytes(input, b";") {
        loop {
            if input.is_empty() || input.starts_with(b"\n") {
                return Some(input);
            }
            input = &input[1..];
        }
    } else {
        None
    }
}

fn consume_nested_comment(input: &[u8]) -> Option<&[u8]> {
    if let Some(mut input) = consume_bytes(input, b"#|") {
        loop {
            if input.is_empty() {
                return None;
            }
            if let Some(input) = consume_bytes(input, b"|#") {
                return Some(input);
            }
            if input.starts_with(b"#|") {
                if let Some(new_input) = consume_nested_comment(input) {
                    input = new_input;
                } else {
                    return None;
                }
            } else {
                input = &input[1..];
            }
        }
    } else {
        None
    }
}

fn consume_datum_comment(input: &[u8]) -> Option<&[u8]> {
    if let Some(input) = consume_bytes(input, b"#;")
        && let Some((_, input)) = consume_expression(consume_whitespace(input))
    {
        Some(input)
    } else {
        None
    }
}

fn consume_whitespace(input: &[u8]) -> &[u8] {
    if input.is_empty() {
        input
    } else if input[0].is_ascii_whitespace() {
        consume_whitespace(&input[1..])
    } else if let Some(input) = consume_line_comment(input) {
        consume_whitespace(input)
    } else if let Some(input) = consume_nested_comment(input) {
        consume_whitespace(input)
    } else if let Some(input) = consume_datum_comment(input) {
        consume_whitespace(input)
    } else {
        input
    }
}

fn consume_expression(input: &[u8]) -> Option<(Token<'_>, &[u8])> {
    if let Some((v, input)) = consume_int(input) {
        Some((Token::Int(v), input))
    } else if let Some((v, input)) = consume_bool(input) {
        Some((Token::Bool(v), input))
    } else if let Some((v, input)) = consume_character(input) {
        Some((Token::Char(v), input))
    } else if let Some((sym, input)) = consume_symbol(input) {
        Some((Token::Symbol(sym), input))
    } else if let Some((args, input)) = consume_form(input) {
        Some((Token::Form(args), input))
    } else if let Some((v, input)) = consume_string_literal(input) {
        Some((Token::String(v), input))
    } else if let Some(input) = consume_null(input) {
        Some((Token::Null, input))
    } else if let Some(input) = consume_dot(input) {
        Some((Token::Dot, input))
    } else {
        None
    }
}

fn consume_expressions(mut input: &[u8]) -> (Vec<Token<'_>>, &[u8]) {
    let mut result = Vec::new();
    while !input.is_empty()
        && let Some((exp, new_input)) = consume_expression(input)
    {
        result.push(exp);
        input = consume_whitespace(new_input);
    }
    (result, input)
}

fn lower_let<'a>(
    mut args: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
    is_tail: bool,
) -> Vec<String> {
    if let Token::Form(bindings) = args.remove(0) {
        let mut binding_names = Vec::new();
        let mut binding_exps = Vec::new();
        for binding in bindings {
            if let Token::Form(mut binding) = binding {
                assert!(
                    binding.len() == 2,
                    "let binding has incorrect argument count."
                );
                binding_exps.push(binding.pop().unwrap());
                binding_names.push(binding.pop().unwrap());
            } else {
                panic!("let binding is not a form")
            }
        }
        for binding_name in &binding_names {
            // Required because Dot can appear in lambda params, but not here.
            assert!(
                matches!(binding_name, Token::Symbol(_)),
                "let binding name is not a symbol"
            );
        }
        let mut lambda = vec![Token::Symbol(b"lambda"), Token::Form(binding_names)];
        lambda.append(&mut args);
        lower_call(
            Token::Form(lambda),
            binding_exps,
            env,
            instructions_emitted,
            is_tail,
        )
    } else {
        panic!("let bindings is not a form")
    }
}

fn lower_letstar<'a>(
    mut args: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
    is_tail: bool,
) -> Vec<String> {
    if let Token::Form(mut bindings) = args.remove(0) {
        if bindings.is_empty() {
            lower_expressions(args, env, instructions_emitted, is_tail)
        } else {
            let first_binding = bindings.remove(0);
            let mut letstar_exp = vec![Token::Symbol(b"let*"), Token::Form(bindings)];
            letstar_exp.append(&mut args);
            lower_let(
                vec![Token::Form(vec![first_binding]), Token::Form(letstar_exp)],
                env,
                instructions_emitted,
                is_tail,
            )
        }
    } else {
        panic!("let* bindings is not a form")
    }
}

fn scan_expression_for_free_variables<'a>(
    exp: &Token<'a>,
    env: &HashMap<&'a [u8], usize>,
    parameters: &HashSet<&'a [u8]>,
) -> HashSet<&'a [u8]> {
    let mut result = HashSet::new();
    match exp {
        // No validation happens here, because it is handled later by codegen
        Token::Form(args) => {
            if let Some(arg0) = args.first() {
                if let Token::Symbol(x) = arg0 {
                    if env.contains_key(x) {
                        // this must be first to allow binding over lambda and let
                        result.extend(scan_expressions_for_free_variables(args, env, parameters));
                    } else {
                        match arg0 {
                            Token::Symbol(b"lambda") => {
                                let mut new_parameters = parameters.clone();
                                if let Some(Token::Form(inner_params)) = args.get(1) {
                                    for inner_param in inner_params {
                                        if let Token::Symbol(inner_param_symbol) = inner_param {
                                            new_parameters.insert(inner_param_symbol);
                                        }
                                    }
                                }
                                result.extend(scan_expressions_for_free_variables(
                                    &args[2..],
                                    env,
                                    &new_parameters,
                                ));
                            }
                            Token::Symbol(b"let") => {
                                let mut new_parameters = parameters.clone();
                                if let Some(Token::Form(bindings)) = args.get(1) {
                                    for binding in bindings {
                                        if let Token::Form(binding_vec) = binding
                                            && let [Token::Symbol(k), v] = binding_vec.as_slice()
                                        {
                                            result.extend(scan_expression_for_free_variables(v, env, parameters /* not let*, so bindings can't use each other. */));
                                            new_parameters.insert(k);
                                        }
                                    }
                                }
                                // If any of the above checks fail, it's fine. codegen will catch it.
                                result.extend(scan_expressions_for_free_variables(
                                    &args[2..],
                                    env,
                                    &new_parameters,
                                ));
                            }
                            Token::Symbol(b"let*") => {
                                let mut new_parameters = parameters.clone();
                                if let Some(Token::Form(bindings)) = args.get(1) {
                                    for binding in bindings {
                                        let mut parameters = parameters.clone();
                                        parameters.extend(new_parameters.clone());
                                        if let Token::Form(binding_vec) = binding
                                            && let [Token::Symbol(k), v] = binding_vec.as_slice()
                                        {
                                            result.extend(scan_expression_for_free_variables(
                                                v,
                                                env,
                                                &parameters,
                                            ));
                                            new_parameters.insert(k);
                                        }
                                    }
                                }
                                // If any of the above checks fail, it's fine. codegen will catch it.
                                result.extend(scan_expressions_for_free_variables(
                                    &args[2..],
                                    env,
                                    &new_parameters,
                                ));
                            }
                            _ => result
                                .extend(scan_expressions_for_free_variables(args, env, parameters)),
                        }
                    }
                } else {
                    result.extend(scan_expressions_for_free_variables(args, env, parameters));
                }
            }
        }
        Token::Symbol(name) => {
            if !parameters.contains(name) && env.contains_key(name) {
                result.insert(name);
            }
        }
        _ => {}
    }
    result
}

fn scan_expressions_for_free_variables<'a>(
    exps: &[Token<'a>],
    env: &HashMap<&'a [u8], usize>,
    parameters: &HashSet<&'a [u8]>,
) -> HashSet<&'a [u8]> {
    let mut result = HashSet::new();
    for exp in exps {
        result.extend(scan_expression_for_free_variables(exp, env, parameters).drain());
    }
    result
}

fn lower_call<'a>(
    func: Token<'a>,
    args: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
    is_tail: bool,
) -> Vec<String> {
    let mut result = Vec::new();
    let mut new_env = env.clone();
    if !is_tail {
        result.push("FRAME".to_owned());
        for v in new_env.values_mut() {
            *v += 1;
        }
    }

    let num_args = args.len();
    for arg in args {
        result.append(&mut lower_expression(
            arg,
            &new_env,
            instructions_emitted + result.len(),
            false,
        ));
        for v in new_env.values_mut() {
            *v += 1;
        }
    }
    result.append(&mut lower_expression(
        func,
        &new_env,
        instructions_emitted + result.len(),
        false,
    ));
    for v in new_env.values_mut() {
        *v += 1;
    }
    result.push(format!("LOAD {num_args} // call arity").to_owned());
    if is_tail {
        result.push("TAILCALL".to_owned());
    } else {
        result.push("CALL".to_owned());
    }
    result
}

fn lower_lambda<'a>(
    mut args: Vec<Token<'a>>,
    lambda_name: Option<&'a [u8]>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
) -> Vec<String> {
    let mut result = Vec::new();
    let mut is_variadic = false;
    let parameters = match args.remove(0) {
        Token::Form(parameters) => parameters,
        Token::Symbol(parameter_list) => {
            is_variadic = true;
            vec![Token::Symbol(parameter_list)]
        }
        _ => panic!("Invalid token type for lambda parameter"),
    };

    let mut parameter_set = HashSet::new();
    let mut parameter_names = Vec::new();
    let mut arity: u64 = parameters.len().try_into().unwrap();
    for (i, parameter) in parameters.into_iter().enumerate() {
        match parameter {
            Token::Symbol(x) => {
                assert!(parameter_set.insert(x), "Duplicate argument in lambda");
                parameter_names.push(x);
            }
            Token::Dot => {
                assert!(
                    !is_variadic,
                    "Encountered multiple Dots in lambda parameters!"
                );
                assert!(
                    i == (arity - 2).try_into().unwrap(),
                    "Dot not in penultimate position"
                );
                is_variadic = true;
                arity -= 1;
            }
            _ => panic!("lambda parameter is not a symbol"),
        }
    }
    let free_var_set = scan_expressions_for_free_variables(args.as_slice(), env, &parameter_set);
    let free_vars: Vec<_> = free_var_set.iter().collect();
    result.append(&mut lower_variadic_primitive(
        "VECTOR",
        0,
        free_vars.iter().map(|x| Token::Symbol(x)).collect(),
        env,
        instructions_emitted + result.len(),
    ));
    result.push(
        format!(
            "LOAD {} // lambda arity",
            if is_variadic { negate_62(arity) } else { arity }
        )
        .to_owned(),
    );
    result.push(
        format!(
            "LAMBDA {}",
            instructions_emitted + result.len() + 1 /* for LAMBDA */ + 1 /* for JUMP */
        )
        .to_owned(),
    );
    let mut lambda_env = HashMap::new();
    // caller pushes args in reverse order
    for p in parameter_names {
        for v in lambda_env.values_mut() {
            *v += 1;
        }
        lambda_env.insert(p, 0);
    }
    // CALL unpacks the freevar vector into the stack in reverse order
    for f in free_vars.into_iter().rev() {
        for v in lambda_env.values_mut() {
            *v += 1;
        }
        lambda_env.insert(f, 0);
    }
    for v in lambda_env.values_mut() {
        *v += 1; // for the lambda
    }
    if let Some(fn_name) = lambda_name {
        lambda_env.insert(fn_name, 0);
    }
    for v in lambda_env.values_mut() {
        *v += 1; // for lr
    }

    let mut lambda_body = lower_expressions(
        args,
        &lambda_env,
        instructions_emitted + result.len() + 1, /* for JUMP */
        true,
    );
    lambda_body.push("RETURN".to_owned());
    result.push(format!("JUMP {}", lambda_body.len()));
    result.append(&mut lambda_body);
    result
}

fn lower_lambdarec<'a>(
    mut args: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
) -> Vec<String> {
    if let Token::Symbol(fn_name) = args.remove(0) {
        lower_lambda(args, Some(fn_name), env, instructions_emitted)
    } else {
        panic!("Invalid lambdarec name")
    }
}

fn lower_if<'a>(
    mut args: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
    is_tail: bool,
) -> Vec<String> {
    let mut result = Vec::new();
    assert!(matches!(args.len(), 2 | 3), "Invalid argument count to if");
    // cond
    result.append(&mut lower_expression(
        args.remove(0),
        env,
        instructions_emitted + result.len(),
        false,
    ));
    result.push("LOAD #f".to_owned());
    result.push("LOAD 2".to_owned());
    result.push("EQP ".to_owned());

    // consequent
    let mut consequent_code = lower_expression(
        args.remove(0),
        env,
        instructions_emitted + result.len() + 1, /* for CJUMP */
        is_tail,
    );

    // alternative
    let mut alternative_code = if let Some(alternative_code) = args.pop() {
        lower_expression(
            alternative_code,
            env,
            instructions_emitted + result.len() + 1 /* for CJUMP */ + consequent_code.len() + 1, /* for JUMP */
            is_tail,
        )
    } else {
        vec!["LOAD UNSPECIFIED".to_owned()]
    };

    consequent_code.push("JUMP ".to_owned() + &alternative_code.len().to_string());

    result.push("CJUMP ".to_owned() + &consequent_code.len().to_string());
    result.append(&mut consequent_code);
    result.append(&mut alternative_code);
    result
}

fn lower_primitive<'a>(
    primitive: &Primitive,
    args: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
) -> Vec<String> {
    if primitive.is_variadic {
        lower_variadic_primitive(
            primitive.mnemonic,
            primitive.minimum_arity,
            args,
            env,
            instructions_emitted,
        )
    } else {
        lower_nary_primitive(
            primitive.mnemonic,
            primitive.minimum_arity,
            args,
            env,
            instructions_emitted,
        )
    }
}

fn lower_nary_primitive<'a>(
    mnemonic: &str,
    n: usize,
    args: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
) -> Vec<String> {
    let mut result = Vec::new();
    assert!(
        args.len() == n,
        "incorrect argument count for {n}-ary primitive"
    );
    let mut new_env = env.clone();
    for arg in args {
        result.append(&mut lower_expression(
            arg,
            &new_env,
            instructions_emitted + result.len(),
            false,
        ));
        for v in new_env.values_mut() {
            *v += 1;
        }
    }
    result.push(mnemonic.to_owned());
    result
}

fn lower_variadic_primitive<'a>(
    mnemonic: &str,
    min_args: usize,
    args: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
) -> Vec<String> {
    let mut result = Vec::new();
    let mut new_env = env.clone();
    let num_args = args.len();
    assert!(
        num_args >= min_args,
        "Too few arguments provided to variadic primitive"
    );
    for arg in args.into_iter().rev() {
        result.append(&mut lower_expression(
            arg,
            &new_env,
            instructions_emitted + result.len(),
            false,
        ));
        for v in new_env.values_mut() {
            *v += 1;
        }
    }
    result.push(format!("LOAD {num_args} // primitive arity"));
    result.push(mnemonic.to_string());
    result
}

fn lower_form<'a>(
    mut args: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
    is_tail: bool,
) -> Vec<String> {
    assert!(!args.is_empty(), "Empty form!");
    let arg_0 = args.remove(0);
    if let Token::Symbol(name) = arg_0 {
        if env.contains_key(name) {
            lower_call(
                Token::Symbol(name),
                args,
                env,
                instructions_emitted,
                is_tail,
            )
        } else {
            match name {
                b"begin" => lower_expressions(args, env, instructions_emitted, is_tail),
                b"apply" => lower_nary_primitive(
                    if is_tail { "APPLY" } else { "TAILAPPLY" },
                    2,
                    args,
                    env,
                    instructions_emitted,
                ),
                b"lambdarec" => lower_lambdarec(args, env, instructions_emitted),
                b"let" => lower_let(args, env, instructions_emitted, is_tail),
                b"let*" => lower_letstar(args, env, instructions_emitted, is_tail),
                b"if" => lower_if(args, env, instructions_emitted, is_tail),
                b"lambda" => lower_lambda(args, None, env, instructions_emitted),
                _ => {
                    if let Some(primitive) = Primitive::from_bytes(name) {
                        lower_primitive(&primitive, args, env, instructions_emitted)
                    } else {
                        panic!("Cannot resolve symbol '{}'", str::from_utf8(name).unwrap())
                    }
                }
            }
        }
    } else {
        lower_call(arg_0, args, env, instructions_emitted, is_tail)
    }
}

fn lower_expression<'a>(
    exp: Token<'a>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
    is_tail: bool,
) -> Vec<String> {
    match exp {
        Token::Int(x) => vec!["LOAD ".to_owned() + &x.to_string()],
        Token::Char(x) => vec![format!("LOAD #\\x{x:x}")],
        Token::Bool(x) => vec!["LOAD ".to_owned() + if x { "#t" } else { "#f" }],
        Token::Form(args) => lower_form(args, env, instructions_emitted, is_tail),
        Token::Null => vec!["LOAD NULL".to_owned()],
        Token::Symbol(name) => {
            if let Some(env_index) = env.get(name) {
                vec!["GET ".to_owned() + &env_index.to_string()]
            } else if let Some(primitive) = Primitive::from_bytes(name) {
                if primitive.is_variadic {
                    vec![
                        "LOAD 0".to_owned(),
                        "VECTOR".to_owned(),
                        format!(
                            "LOAD {}",
                            negate_62((primitive.minimum_arity + 1).try_into().unwrap())
                        ),
                        format!("LAMBDA {}", instructions_emitted + 5),
                        "JUMP 2".to_owned(),
                        format!("PRIMAPPLY {}", primitive.mnemonic),
                        "RETURN".to_owned(),
                    ]
                } else {
                    let mut code = Vec::new();
                    code.extend_from_slice(b"(lambda (");

                    for i in 0..primitive.minimum_arity {
                        code.extend_from_slice(format!(" arg{i}").as_bytes());
                    }
                    code.extend_from_slice(b") (");
                    code.extend_from_slice(name);
                    for i in 0..primitive.minimum_arity {
                        code.extend_from_slice(format!(" arg{i}").as_bytes());
                    }
                    code.extend_from_slice(b"))");
                    let mut ast = parse(code.as_slice());
                    assert!(ast.len() == 1);
                    lower_expression(ast.remove(0), env, instructions_emitted, is_tail)
                }
            } else {
                panic!(
                    "Couldn't find environment entry for \"{}\"",
                    str::from_utf8(name).unwrap()
                )
            }
        }
        Token::String(v) => lower_variadic_primitive(
            "STRING",
            0,
            v.into_iter().map(Token::Char).collect(),
            env,
            instructions_emitted,
        ),
        Token::Dot => panic!("Dot is invalid in this context!"),
    }
}

fn lower_expressions<'a>(
    exps: Vec<Token<'a>>,
    env: &HashMap<&'a [u8], usize>,
    instructions_emitted: usize,
    is_tail: bool,
) -> Vec<String> {
    if exps.is_empty() {
        vec!["LOAD UNSPECIFIED".to_owned()]
    } else {
        let mut result = Vec::new();
        let num_exps = exps.len();
        for (i, exp) in exps.into_iter().enumerate() {
            let is_last = i == num_exps - 1;
            result.append(&mut lower_expression(
                exp,
                env,
                instructions_emitted + result.len(),
                is_tail && is_last,
            ));
            if !is_last {
                result.push("FORGET".to_owned());
            }
        }
        result
    }
}

fn parse(input_slice: &[u8]) -> Vec<Token<'_>> {
    let (ast, input_slice) = consume_expressions(consume_whitespace(input_slice));
    assert!(
        input_slice.is_empty(),
        "Parsing failed. Leftover data: {}",
        str::from_utf8(input_slice).unwrap(),
    );
    ast
}

fn codegen(ast: Vec<Token>) -> Vec<String> {
    lower_expressions(ast, &HashMap::new(), 0, false)
}

fn main() {
    let mut input_vec = Vec::new();
    input_vec.extend_from_slice(
        b"(let* (
            (list (lambda args args)) ; isn't this cool?
            (reverse
                (lambda (l)
                    ((lambdarec reverse-tail (l acc)
                        (if (null? l)
                            acc
                            (reverse-tail (cdr l) (cons (car l) acc)))) l '())))
            (fold
                (lambdarec fold (f i l)
                    (if (null? l)
                        i
                        (fold f (f (car l) i) (cdr l)))))
            (foldr (lambda (f i l) (fold f i (reverse l))))
            (map
                (lambda (f l)
                    (foldr (lambda (h t) (cons (f h) t)) '() l))))",
    );
    let _bytes_read = stdin().read_to_end(&mut input_vec);
    input_vec.extend_from_slice(b")");
    let mut user_code = codegen(parse(input_vec.as_slice()));
    user_code.push("DONE".to_owned());
    println!("{}", user_code.join("\n"));
}

#[test]
#[should_panic(expected = "let bindings is not a form")]
fn invalid_let_binding_list() {
    codegen(parse(b"(let 1 1)"));
}

#[test]
#[should_panic(expected = "let binding is not a form")]
fn invalid_let_binding_list_entry() {
    codegen(parse(b"(let (1) 1)"));
}

#[test]
#[should_panic(expected = "let binding has incorrect argument count.")]
fn let_binding_too_many_args() {
    codegen(parse(b"(let ((x 1 1)) x)"));
}

#[test]
#[should_panic(expected = "Duplicate argument in lambda")]
fn let_binding_duplicate_key() {
    codegen(parse(b"(let ((x 1) (x 1)) x)"));
}

#[test]
#[should_panic(expected = "let binding is not a form")]
fn let_binding_list_not_nested() {
    codegen(parse(b"(let (x 1) x)"));
}

#[test]
#[should_panic(expected = "Invalid argument count to if")]
fn too_few_if_args() {
    codegen(parse(b"(if)"));
}

#[test]
#[should_panic(expected = "Invalid argument count to if")]
fn too_many_if_args() {
    codegen(parse(b"(if 1 2 3 4)"));
}

#[test]
#[should_panic(expected = "Parsing failed. Leftover data: ]")]
fn leftover_data() {
    codegen(parse(b"]"));
}

#[test]
#[should_panic(expected = "incorrect argument count for 1-ary primitive")]
fn too_few_unary_args() {
    codegen(parse(b"(not)"));
}

#[test]
#[should_panic(expected = "incorrect argument count for 1-ary primitive")]
fn too_many_unary_args() {
    codegen(parse(b"(not 1 2)"));
}

#[test]
#[should_panic(expected = "Couldn't find environment entry for \"a\"")]
fn use_undefined_variable() {
    codegen(parse(b"a"));
}

#[test]
#[should_panic(expected = "Parsing failed. Leftover data: #| #| |#")]
fn mismatched_nested_comment() {
    codegen(parse(b"#| #| |#"));
}

#[test]
#[should_panic(expected = "let binding name is not a symbol")]
fn numeric_symbol() {
    codegen(parse(b"(let ((1 0)) 1)"));
}
