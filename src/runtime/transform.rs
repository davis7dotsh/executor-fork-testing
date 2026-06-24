use std::path::Path;

use oxc::{
    allocator::Allocator,
    ast::ast::{
        BindingPattern, CallExpression, Decorator, ExportDefaultDeclarationKind, Expression,
        ImportDeclaration, ImportExpression, JSXElement, JSXFragment, Program, Statement,
        TSEnumDeclaration, TSModuleDeclaration,
    },
    ast_visit::{Visit, walk},
    codegen::Codegen,
    parser::Parser,
    semantic::SemanticBuilder,
    span::{GetSpan, SourceType},
    transformer::{TransformOptions, Transformer},
};

use super::{MAX_SOURCE_BYTES, RuntimeFailure};

pub(crate) fn recover_and_transform(input: &str) -> Result<String, RuntimeFailure> {
    if input.len() > MAX_SOURCE_BYTES {
        return Err(RuntimeFailure::public(
            "source_too_large",
            "TypeScript source exceeded 1 MiB",
        ));
    }
    let recovered = first_fenced_block(input).unwrap_or(input).trim();
    let wrapped = wrap_entrypoint(recovered)?;

    let allocator = Allocator::default();
    let source_type = SourceType::ts().with_module(true);
    let parsed = Parser::new(&allocator, &wrapped, source_type).parse();
    if !parsed.diagnostics.is_empty() {
        return Err(RuntimeFailure::public(
            "typescript_invalid",
            "TypeScript could not be parsed",
        ));
    }
    let mut program = parsed.program;
    validate_program(&program)?;
    let semantic = SemanticBuilder::new().with_enum_eval(true).build(&program);
    if !semantic.diagnostics.is_empty() {
        return Err(RuntimeFailure::public(
            "typescript_invalid",
            "TypeScript semantic analysis failed",
        ));
    }
    let transformed = Transformer::new(
        &allocator,
        Path::new("executor-input.ts"),
        &TransformOptions::default(),
    )
    .build_with_scoping(semantic.semantic.into_scoping(), &mut program);
    if !transformed.diagnostics.is_empty() {
        return Err(RuntimeFailure::public(
            "typescript_unsupported",
            "TypeScript used unsupported syntax",
        ));
    }
    let output = Codegen::new().build(&program).code;
    if output.len() > MAX_SOURCE_BYTES {
        return Err(RuntimeFailure::public(
            "transformed_source_too_large",
            "transformed JavaScript exceeded 1 MiB",
        ));
    }
    Ok(output)
}

fn first_fenced_block(input: &str) -> Option<&str> {
    let start = input.find("```")?;
    let after_ticks = &input[start + 3..];
    let body_start = after_ticks.find('\n').map_or(0, |index| index + 1);
    let body = &after_ticks[body_start..];
    let end = body.find("```")?;
    Some(&body[..end])
}

fn validate_program(program: &Program<'_>) -> Result<(), RuntimeFailure> {
    let mut validator = UnsupportedSyntax::default();
    validator.visit_program(program);
    match validator.unsupported {
        Some(name) => Err(RuntimeFailure::public(
            "typescript_unsupported",
            format!("{name} are not supported"),
        )),
        None => Ok(()),
    }
}

#[derive(Default)]
struct UnsupportedSyntax {
    unsupported: Option<&'static str>,
}

impl<'a> Visit<'a> for UnsupportedSyntax {
    fn visit_import_declaration(&mut self, _: &ImportDeclaration<'a>) {
        self.unsupported.get_or_insert("imports");
    }

    fn visit_import_expression(&mut self, _: &ImportExpression<'a>) {
        self.unsupported.get_or_insert("dynamic imports");
    }

    fn visit_call_expression(&mut self, expression: &CallExpression<'a>) {
        if matches!(&expression.callee, Expression::Identifier(identifier) if identifier.name == "require")
        {
            self.unsupported.get_or_insert("module loading");
        }
        walk::walk_call_expression(self, expression);
    }

    fn visit_ts_enum_declaration(&mut self, _: &TSEnumDeclaration<'a>) {
        self.unsupported.get_or_insert("TypeScript enums");
    }

    fn visit_ts_module_declaration(&mut self, _: &TSModuleDeclaration<'a>) {
        self.unsupported.get_or_insert("TypeScript namespaces");
    }

    fn visit_decorator(&mut self, _: &Decorator<'a>) {
        self.unsupported.get_or_insert("decorators");
    }

    fn visit_jsx_element(&mut self, _: &JSXElement<'a>) {
        self.unsupported.get_or_insert("JSX elements");
    }

    fn visit_jsx_fragment(&mut self, _: &JSXFragment<'a>) {
        self.unsupported.get_or_insert("JSX fragments");
    }
}

fn wrap_entrypoint(source: &str) -> Result<String, RuntimeFailure> {
    if source.is_empty() {
        return Err(RuntimeFailure::public(
            "typescript_invalid",
            "TypeScript source was empty",
        ));
    }
    let trimmed = source.trim();
    match classify_entrypoint(trimmed)? {
        Entrypoint::Body => Ok(format!(
            "globalThis.__executor_entry = (async () => {{ {trimmed}\n }})();"
        )),
        Entrypoint::Named(name) => Ok(format!(
            "globalThis.__executor_entry = (async () => {{ {trimmed}; return await {name}(); }})();"
        )),
        Entrypoint::Expression => Ok(format!(
            "globalThis.__executor_entry = (async () => {{ const entry = ({trimmed}); return await entry(); }})();"
        )),
        Entrypoint::Default { start, end } => {
            let expression = trimmed[start..end].trim_end_matches(';').trim_end();
            Ok(format!(
                "globalThis.__executor_entry = (async () => {{ const entry = ({expression}); return await entry(); }})();"
            ))
        }
    }
}

enum Entrypoint {
    Body,
    Named(String),
    Expression,
    Default { start: usize, end: usize },
}

fn classify_entrypoint(source: &str) -> Result<Entrypoint, RuntimeFailure> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::ts().with_module(true)).parse();
    if !parsed.diagnostics.is_empty() {
        let expression_source = format!("({source})");
        let expression_allocator = Allocator::default();
        let expression = Parser::new(
            &expression_allocator,
            &expression_source,
            SourceType::ts().with_module(true),
        )
        .parse();
        if expression.diagnostics.is_empty() {
            validate_program(&expression.program)?;
            if matches!(
                expression.program.body.first(),
                Some(Statement::ExpressionStatement(statement))
                    if is_callable_expression(&statement.expression)
            ) {
                return Ok(Entrypoint::Expression);
            }
        }
        return Ok(Entrypoint::Body);
    }
    validate_program(&parsed.program)?;
    let Some(first) = parsed.program.body.first() else {
        return Ok(Entrypoint::Body);
    };
    match first {
        Statement::FunctionDeclaration(function) => {
            Ok(function.id.as_ref().map_or(Entrypoint::Body, |id| {
                Entrypoint::Named(id.name.to_string())
            }))
        }
        Statement::VariableDeclaration(declaration) => {
            let Some(variable) = declaration.declarations.first() else {
                return Ok(Entrypoint::Body);
            };
            let callable = variable.init.as_ref().is_some_and(is_callable_expression);
            match (&variable.id, callable) {
                (BindingPattern::BindingIdentifier(identifier), true) => {
                    Ok(Entrypoint::Named(identifier.name.to_string()))
                }
                _ => Ok(Entrypoint::Body),
            }
        }
        Statement::ExpressionStatement(statement)
            if is_callable_expression(&statement.expression) =>
        {
            Ok(Entrypoint::Expression)
        }
        Statement::ExportDefaultDeclaration(declaration)
            if matches!(
                declaration.declaration,
                ExportDefaultDeclarationKind::FunctionDeclaration(_)
                    | ExportDefaultDeclarationKind::ArrowFunctionExpression(_)
                    | ExportDefaultDeclarationKind::FunctionExpression(_)
            ) =>
        {
            let span = declaration.declaration.span();
            Ok(Entrypoint::Default {
                start: span.start as usize,
                end: span.end as usize,
            })
        }
        _ => Ok(Entrypoint::Body),
    }
}

fn is_callable_expression(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => true,
        Expression::ParenthesizedExpression(parenthesized) => {
            is_callable_expression(&parenthesized.expression)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_first_fenced_block_and_removes_types() {
        let output = recover_and_transform(
            "before\n```ts\nconst value: number = 2; return value\n```\nafter",
        )
        .expect("source should transform");
        assert!(output.contains("const value = 2"));
        assert!(!output.contains(": number"));
        assert!(!output.contains("after"));
    }

    #[test]
    fn supports_function_and_default_export_entries() {
        assert!(
            recover_and_transform("async function main(): Promise<number> { return 4 }")
                .expect("declaration should transform")
                .contains("main()")
        );
        assert!(
            recover_and_transform("export default async () => 5;")
                .expect("default export should transform")
                .contains("entry()")
        );
        assert!(
            recover_and_transform("const main = async function (): Promise<number> { return 6 }")
                .expect("callable variable should transform")
                .contains("main()")
        );
        assert!(
            recover_and_transform("function $main() { return 7 }")
                .expect("dollar identifier should transform")
                .contains("$main()")
        );
        assert!(
            recover_and_transform("const main=async function() { return 8 }")
                .expect("compact callable variable should transform")
                .contains("main()")
        );
        assert!(
            recover_and_transform("async function () { return 9 }")
                .expect("anonymous function expression should transform")
                .contains("entry()")
        );
    }

    #[test]
    fn rejects_capabilities_and_unsupported_syntax() {
        for source in [
            "import x from 'x'",
            "return import('x')",
            "enum X { A }",
            "@sealed class X {}",
            "return <div />",
        ] {
            let code = recover_and_transform(source)
                .expect_err("source must be rejected")
                .code;
            assert!(
                matches!(
                    code.as_str(),
                    "typescript_unsupported" | "typescript_invalid"
                ),
                "unexpected rejection code for {source}: {code}"
            );
        }
    }

    #[test]
    fn unsupported_markers_inside_strings_and_comments_are_data() {
        recover_and_transform(
            r#"// import is documentation
            const email = "person@example.com";
            return { email, note: "enum import require(" };"#,
        )
        .expect("string and comment contents should not be syntax");
        recover_and_transform("return /@/.test('x');")
            .expect("regular expression contents should remain data");
    }

    #[test]
    fn rejects_unsupported_syntax_nested_in_templates_without_panicking() {
        let error = recover_and_transform("return `${(() => { enum X { A }; return X.A })()}`;")
            .expect_err("nested enum must be rejected");
        assert_eq!(error.code, "typescript_unsupported");
    }
}
