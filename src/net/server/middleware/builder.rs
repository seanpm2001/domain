//! Middleware builders.
use std::{boxed::Box, vec::Vec};

use octseq::Octets;

use crate::base::wire::Composer;

use super::{
    chain::MiddlewareChain, processor::MiddlewareProcessor,
    processors::mandatory::MandatoryMiddlewareProcessor,
};

/// A [`MiddlewareChain`] builder.
///
/// A [`MiddlewareChain`] is immutable and so cannot be constructed one
/// [`MiddlewareProcessor`] at a time.
///
/// This builder allows you to add [`MiddlewareProcessor`]s sequentially using
/// [`push()`] before finally calling [`finish()`] to turn the builder into an
/// immutable [`MiddlewareChain`].
///
/// [`push()`]: Self::push()
/// [`finish()`]: Self::finish()
pub struct MiddlewareBuilder<RequestOctets = Vec<u8>, Target = Vec<u8>>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    processors: Vec<
        Box<dyn MiddlewareProcessor<RequestOctets, Target> + Sync + Send>,
    >,
}

impl<RequestOctets, Target> MiddlewareBuilder<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    /// Create a new builder.
    ///
    /// <div class="warning">Warning:
    ///
    /// When building a standards compliant DNS server you should probably use
    /// [`MiddlewareBuilder::default()`] instead.
    /// </div>
    ///
    /// [`MiddlewareBuilder::default()`]: Self::default()
    #[must_use]
    pub fn new() -> Self {
        Self { processors: vec![] }
    }

    /// Add a [`MiddlewareProcessor`] to the end of the chain.
    ///
    /// Processors later in the chain pre-process requests after, and
    /// post-process responses before, than processors earlier in the chain.
    pub fn push<T>(&mut self, processor: T)
    where
        T: MiddlewareProcessor<RequestOctets, Target> + Sync + Send + 'static,
    {
        self.processors.push(Box::new(processor));
    }

    /// Turn the builder into an immutable [`MiddlewareChain`].
    #[must_use]
    pub fn finish(self) -> MiddlewareChain<RequestOctets, Target> {
        MiddlewareChain::new(self.processors)
    }
}

impl<RequestOctets, Target> Default
    for MiddlewareBuilder<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]> + Octets,
    Target: Composer + Default,
{
    /// Create a builder with default configuration.
    ///
    /// The default configuration pre-populates the builder with an initial
    /// [`MandatoryMiddlewareProcessor`] in the chain.
    ///
    /// This is the default because most normal DNS servers probably need to
    /// comply with applicable RFC standards for DNS servers, only special
    /// cases like testing and research may want a chain that doesn't start
    /// with the mandatory processor.
    ///
    /// [`MandatoryMiddlewareProcessor`]: crate::net::server::middleware::processors::mandatory::MandatoryMiddlewareProcessor
    #[must_use]
    fn default() -> Self {
        let mut builder = Self::new();
        builder.push(MandatoryMiddlewareProcessor::new());
        builder
    }
}