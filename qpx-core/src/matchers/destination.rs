use crate::config::{DestinationDimensionMatchConfig, DestinationMatchConfig};
use crate::prefilter::{StringInterner, TextPatternMatcher, compile_text_patterns};
use crate::rules::RuleMatchContext;

use super::Result;
use super::identity::match_optional_text;
use super::numeric::{CompiledNumericMatcher, compile_numeric_matchers, match_optional_numeric};

#[derive(Debug, Clone)]
pub(super) struct CompiledDestinationMatch {
    category: CompiledDestinationDimensionMatch,
    reputation: CompiledDestinationDimensionMatch,
    application: CompiledDestinationDimensionMatch,
}

#[derive(Debug, Clone, Default)]
struct CompiledDestinationDimensionMatch {
    value: Option<TextPatternMatcher>,
    source: Option<TextPatternMatcher>,
    confidence: Option<CompiledNumericMatcher>,
}

impl CompiledDestinationMatch {
    pub(super) fn compile(
        config: Option<&DestinationMatchConfig>,
        interner: &mut StringInterner,
    ) -> Result<Option<Self>> {
        let Some(config) = config else {
            return Ok(None);
        };
        Ok(Some(Self {
            category: CompiledDestinationDimensionMatch::compile(
                config.category.as_ref(),
                interner,
            )?,
            reputation: CompiledDestinationDimensionMatch::compile(
                config.reputation.as_ref(),
                interner,
            )?,
            application: CompiledDestinationDimensionMatch::compile(
                config.application.as_ref(),
                interner,
            )?,
        }))
    }

    pub(super) fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.category.matches(
            ctx.destination_category,
            ctx.destination_category_source,
            ctx.destination_category_confidence,
        ) && self.reputation.matches(
            ctx.destination_reputation,
            ctx.destination_reputation_source,
            ctx.destination_reputation_confidence,
        ) && self.application.matches(
            ctx.destination_application,
            ctx.destination_application_source,
            ctx.destination_application_confidence,
        )
    }
}

impl CompiledDestinationDimensionMatch {
    fn compile(
        config: Option<&DestinationDimensionMatchConfig>,
        interner: &mut StringInterner,
    ) -> Result<Self> {
        let Some(config) = config else {
            return Ok(Self::default());
        };
        let (value, _) = compile_text_patterns(&config.value, true, false, interner)?;
        let (source, _) = compile_text_patterns(&config.source, true, false, interner)?;
        let confidence = compile_numeric_matchers(&config.confidence)?;
        Ok(Self {
            value,
            source,
            confidence,
        })
    }

    fn matches(&self, value: Option<&str>, source: Option<&str>, confidence: Option<u64>) -> bool {
        match_optional_text(&self.value, value)
            && match_optional_text(&self.source, source)
            && match_optional_numeric(&self.confidence, confidence)
    }
}
