//! The application logic of a DNS server.
//!
//! The [`Service::call()`] function defines how the service should respond to
//! a given DNS request. resulting in a [`ServiceResult`] containing a
//! transaction that yields one or more future DNS responses, and/or a
//! [`ServiceFeedback`].
use core::fmt::Display;
use core::ops::Deref;

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use futures_util::stream::FuturesOrdered;
use futures_util::{FutureExt, StreamExt};
use octseq::{OctetsBuilder, ShortBuf};

use crate::base::iana::Rcode;
use crate::base::message_builder::{AdditionalBuilder, PushError};
use crate::base::wire::{Composer, ParseError};
use crate::base::{Message, StreamTarget};

use super::message::Request;

//------------ Service -------------------------------------------------------

/// [`Service`]s are responsible for determining how to respond to valid DNS
/// requests.
///
/// A request is "valid" if it passed successfully through the underlying
/// server (e.g. [`DgramServer`] or [`StreamServer`]) and [`MiddlewareChain`]
/// stages.
///
/// For an overview of how services fit into the total flow of request and
/// response handling see the [net::server module documentation].
///
/// Each [`Service`] implementation defines a [`call()`] function which takes
/// a [`Request`] DNS request as input and returns either a
/// [`Transaction`] on success, or a [`ServiceError`] on failure, as output.
///
/// Each [`Transaction`] contains either a single DNS response message, or a
/// stream of DNS response messages (e.g. for a zone transfer). Each response
/// message is returned as a [`Future`] which the underlying server will
/// resolve to a [`CallResult`].
///
/// # Usage
///
/// There are three ways to implement the [`Service`] trait:
///
///   1. Implement the [`Service`] trait on a struct.
///   2. Define a function compatible with the [`Service`] trait.
///   3. Define a function compatible with [`service_fn()`].
///
/// Whichever approach you choose it is important to minimize the work done
/// before returning from [`Service::call()`], as time spent here blocks the
/// caller. Instead as much work as possible should be delegated to the
/// futures returned as a [`Transaction`].
///
/// # Implementing the [`Service`] trait on a `struct`
///
/// ```
/// use core::future::ready;
/// use core::future::Ready;
/// use domain::base::iana::Class;
/// use domain::base::iana::Rcode;
/// use domain::base::message_builder::AdditionalBuilder;
/// use domain::base::Dname;
/// use domain::base::MessageBuilder;
/// use domain::base::StreamTarget;
/// use domain::net::server::prelude::*;
/// use domain::rdata::A;
///
/// fn mk_answer(
///     msg: &Request<Message<Vec<u8>>>,
///     builder: MessageBuilder<StreamTarget<Vec<u8>>>,
/// ) -> Result<AdditionalBuilder<StreamTarget<Vec<u8>>>, ServiceError> {
///     let mut answer = builder.start_answer(msg.message(), Rcode::NoError)?;
///     answer.push((
///         Dname::root_ref(),
///         Class::In,
///         86400,
///         A::from_octets(192, 0, 2, 1),
///     ))?;
///     Ok(answer.additional())
/// }
///
/// struct MyService;
///
/// impl Service<Vec<u8>> for MyService {
///     type Target = Vec<u8>;
///     type Future = Ready<Result<CallResult<Vec<u8>, Self::Target>, ServiceError>>;
///
///     fn call(
///         &self,
///         msg: Request<Message<Vec<u8>>>,
///     ) -> Result<
///             Transaction<
///             Result<CallResult<Vec<u8>, Self::Target>, ServiceError>,
///             Self::Future,
///         >,
///         ServiceError,
///     > {
///         let builder = mk_builder_for_target();
///         let additional = mk_answer(&msg, builder)?;
///         let item = ready(Ok(CallResult::new(additional)));
///         let txn = Transaction::single(item);
///         Ok(txn)
///     }
/// }
/// ```
///
/// # Define a function compatible with the [`Service`] trait
///
/// ```
/// use core::future::ready;
/// use core::future::Future;
/// use domain::base::iana::Class;
/// use domain::base::iana::Rcode;
/// use domain::base::name::ToLabelIter;
/// use domain::base::Dname;
/// use domain::net::server::prelude::*;
/// use domain::rdata::A;
///
/// fn name_to_ip<Target>(
///     msg: Request<Message<Vec<u8>>>,
/// ) -> Result<
///     Transaction<
///         Result<CallResult<Vec<u8>, Target>, ServiceError>,
///         impl Future<
///             Output = Result<
///                 CallResult<Vec<u8>, Target>,
///                 ServiceError,
///             >,
///         > + Send,
///     >,
///     ServiceError,
/// >
/// where
///     Target: Composer + Octets + FreezeBuilder<Octets = Target> + Default + Send,
///     <Target as octseq::OctetsBuilder>::AppendError: Debug,
/// {
///     let mut out_answer = None;
///     if let Ok(question) = msg.message().sole_question() {
///         let qname = question.qname();
///         let num_labels = qname.label_count();
///         if num_labels >= 5 {
///             let mut iter = qname.iter_labels();
///             let a = iter.nth(num_labels - 5).unwrap();
///             let b = iter.next().unwrap();
///             let c = iter.next().unwrap();
///             let d = iter.next().unwrap();
///             let a_rec: Result<A, _> = format!("{a}.{b}.{c}.{d}").parse();
///             if let Ok(a_rec) = a_rec {
///                 let builder = mk_builder_for_target();
///                 let mut answer =
///                     builder
///                         .start_answer(msg.message(), Rcode::NoError)
///                         .unwrap();
///                 answer
///                     .push((Dname::root_ref(), Class::In, 86400, a_rec))
///                     .unwrap();
///                 out_answer = Some(answer);
///             }
///         }
///     }
///
///     if out_answer.is_none() {
///         let builder = mk_builder_for_target();
///         let answer = builder
///             .start_answer(msg.message(), Rcode::Refused)
///             .unwrap();
///         out_answer = Some(answer);
///     }
///
///     let additional = out_answer.unwrap().additional();
///     let item = Ok(CallResult::new(additional));
///     Ok(Transaction::single(ready(item)))
/// }
/// ```
///
/// Now when you want to use the service pass it to the server:
///
/// ```ignore
/// let srv = DgramServer::new(sock, buf, name_to_ip);
/// ```
///
/// # Define a function compatible with [`service_fn()`]
///
/// See [`service_fn()`] for an example of how to use it to create a
/// [`Service`] impl from a funciton.
///
/// [`MiddlewareChain`]: crate::net::server::middleware::chain::MiddlewareChain
/// [`DgramServer`]: crate::net::server::dgram::DgramServer
/// [`StreamServer`]: crate::net::server::stream::StreamServer
/// [net::server module documentation]: crate::net::server
/// [`call()`]: Self::call()
/// [`service_fn()`]: crate::net::server::util::service_fn()
pub trait Service<RequestOctets: AsRef<[u8]> = Vec<u8>> {
    /// The type of buffer in which [`ServiceResultItem`]s are stored.
    type Target: Composer + Default + Send + Sync + 'static;

    /// The type of future returned by [`Service::call()`] via
    /// [`Transaction::single()`].
    type Future: std::future::Future<
            Output = Result<
                CallResult<RequestOctets, Self::Target>,
                ServiceError,
            >,
        > + Send;

    /// Generate a response to a fully pre-processed request.
    #[allow(clippy::type_complexity)]
    fn call(
        &self,
        message: Request<Message<RequestOctets>>,
    ) -> Result<
        Transaction<
            Result<CallResult<RequestOctets, Self::Target>, ServiceError>,
            Self::Future,
        >,
        ServiceError,
    >;
}

/// Helper trait impl to treat an [`Arc<impl Service>`] as a [`Service`].
impl<RequestOctets: AsRef<[u8]>, T: Service<RequestOctets>>
    Service<RequestOctets> for Arc<T>
{
    type Target = T::Target;
    type Future = T::Future;

    fn call(
        &self,
        message: Request<Message<RequestOctets>>,
    ) -> Result<
        Transaction<
            Result<CallResult<RequestOctets, Self::Target>, ServiceError>,
            Self::Future,
        >,
        ServiceError,
    > {
        Arc::deref(self).call(message)
    }
}

/// Helper trait impl to treat a function as a [`Service`].
impl<RequestOctets, Target, Future, F> Service<RequestOctets> for F
where
    F: Fn(
        Request<Message<RequestOctets>>,
    ) -> Result<
        Transaction<
            Result<CallResult<RequestOctets, Target>, ServiceError>,
            Future,
        >,
        ServiceError,
    >,
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default + Send + Sync + 'static,
    Future: std::future::Future<
            Output = Result<CallResult<RequestOctets, Target>, ServiceError>,
        > + Send,
{
    type Target = Target;
    type Future = Future;

    fn call(
        &self,
        message: Request<Message<RequestOctets>>,
    ) -> Result<
        Transaction<
            Result<CallResult<RequestOctets, Self::Target>, ServiceError>,
            Self::Future,
        >,
        ServiceError,
    > {
        (*self)(message)
    }
}

//------------ ServiceError --------------------------------------------------

/// An error reported by a [`Service`].
#[derive(Debug)]
pub enum ServiceError {
    /// The service was unable to parse the request.
    FormatError,

    /// The service encountered a service-specific error condition.
    InternalError,

    /// The service was unable to assemble the response.
    NotImplemented,

    /// The service declined to handle the request.
    Refused,
}

impl ServiceError {
    pub fn rcode(&self) -> Rcode {
        match self {
            Self::FormatError => Rcode::FormErr,
            Self::InternalError => Rcode::ServFail,
            Self::NotImplemented => Rcode::NotImp,
            Self::Refused => Rcode::Refused,
        }
    }
}

//--- Display

impl Display for ServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FormatError => write!(f, "Format error"),
            Self::InternalError => write!(f, "Internal error"),
            Self::NotImplemented => write!(f, "Not implemented"),
            Self::Refused => write!(f, "Refused"),
        }
    }
}

//--- From<PushError>

impl From<PushError> for ServiceError {
    fn from(_: PushError) -> Self {
        Self::InternalError
    }
}

//--- From<ParseError>

impl From<ParseError> for ServiceError {
    fn from(_: ParseError) -> Self {
        Self::FormatError
    }
}

//------------ ServiceFeedback -----------------------------------------------

/// Feedback from a [`Service`] to a server asking it to do something.
#[derive(Copy, Clone, Debug)]
pub enum ServiceFeedback {
    /// Ask the server to alter its configuration.
    Reconfigure { idle_timeout: Duration },

    /// Ask the connection handler to terminate.
    ///
    /// This command is only applicable to connection-oriented
    /// transport protocols.
    CloseConnection,

    /// Ask the server to shutdown.
    Shutdown,
}

//------------ CallResult ----------------------------------------------------

/// The result of processing a DNS request via [`Service::call()`].
///
/// Directions to a server on how to respond to a request.
///
/// In most cases a [`CallResult`] will be a DNS response message.
///
/// If needed a [`CallResult`] can instead, or additionally, contain a
/// [`ServiceFeedback`] directing the server or connection handler handling the
/// request to adjust its own configuration, or even to terminate the
/// connection.
#[derive(Clone, Debug)]
pub struct CallResult<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
{
    request: Option<Request<Message<RequestOctets>>>,
    response: Option<AdditionalBuilder<StreamTarget<Target>>>,
    feedback: Option<ServiceFeedback>,
}

type RequestMsg<RequestOctets> = Request<Message<RequestOctets>>;
type ResponseMsg<Target> = AdditionalBuilder<StreamTarget<Target>>;

impl<RequestOctets, Target> CallResult<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Target::AppendError: Into<ShortBuf>,
{
    /// Construct a [`CallResult`] from a DNS response message.
    #[must_use]
    pub fn new(response: AdditionalBuilder<StreamTarget<Target>>) -> Self {
        Self {
            request: None,
            response: Some(response),
            feedback: None,
        }
    }

    /// Construct a [`CallResult`] from a [`ServiceFeedback`].
    #[must_use]
    pub fn feedback_only(command: ServiceFeedback) -> Self {
        Self {
            request: None,
            response: None,
            feedback: Some(command),
        }
    }

    /// Add an [`Request<_>`] to an existing [`CallResult`].
    #[must_use]
    pub fn with_request(
        mut self,
        request: Request<Message<RequestOctets>>,
    ) -> Self {
        self.request = Some(request);
        self
    }

    /// Add a [`ServiceFeedback`] to an existing [`CallResult`].
    #[must_use]
    pub fn with_feedback(mut self, feedback: ServiceFeedback) -> Self {
        self.feedback = Some(feedback);
        self
    }

    /// Get the contained feedback, if any.
    #[must_use]
    pub fn feedback(&self) -> Option<ServiceFeedback> {
        self.feedback
    }

    /// Get a mutable reference to the contained DNS response message, if any.
    #[must_use]
    pub fn get_response_mut(
        &mut self,
    ) -> Option<&mut AdditionalBuilder<StreamTarget<Target>>> {
        self.response.as_mut()
    }

    /// Convert the [`CallResult`] into the contained DNS response message and command.
    #[must_use]
    pub fn into_inner(
        self,
    ) -> (
        Option<RequestMsg<RequestOctets>>,
        Option<ResponseMsg<Target>>,
        Option<ServiceFeedback>,
    ) {
        let CallResult {
            request,
            response,
            feedback,
        } = self;
        (request, response, feedback)
    }
}

//------------ Transaction ---------------------------------------------------

/// Zero or more DNS response futures relating to a single DNS request.
///
/// A transaction is either empty, a single DNS response future, or a stream
/// of DNS response futures.
///
/// # Usage
///
/// Either:
///   - Construct a transaction for a [`single()`] response future, OR
///   - Construct a transaction [`stream()`] and [`push()`] response futures
///     into it.
///
/// Then iterate over the response futures one at a time using [`next()`].
///
/// [`single()`]: Self::single()
/// [`stream()`]: Self::stream()
/// [`push()`]: TransactionStream::push()
/// [`next()`]: Self::next()
pub struct Transaction<Item, Future>(TransactionInner<Item, Future>)
where
    Future: std::future::Future<Output = Item> + Send;

impl<Item, Future> Transaction<Item, Future>
where
    Future: std::future::Future<Output = Item> + Send,
{
    /// Construct a transaction for a single immediate response.
    pub(crate) fn immediate(item: Item) -> Self {
        Self(TransactionInner::Immediate(Some(item)))
    }

    /// Construct an empty transaction.
    pub fn empty() -> Self {
        Self(TransactionInner::Single(None))
    }

    /// Construct a transaction for a single response future.
    pub fn single(fut: Future) -> Self {
        Self(TransactionInner::Single(Some(fut)))
    }

    /// Construct a transaction for a future stream of response futures.
    ///
    /// The given future should build the stream of response futures that will
    /// eventually be resolved by [`Self::next()`].
    ///
    /// This takes a future instead of a [`TransactionStream`] because the
    /// caller may not yet know how many futures they need to push into the
    /// stream and we don't want them to block us while they work that out.
    pub fn stream(
        fut: Pin<
            Box<
                dyn std::future::Future<Output = TransactionStream<Item>>
                    + Send,
            >,
        >,
    ) -> Self {
        Self(TransactionInner::PendingStream(fut))
    }

    /// Take the next response from the transaction, if any.
    ///
    /// This function provides a single way to take futures from the
    /// transaction without needing to handle which type of transaction it is.
    ///
    /// Returns None if there are no (more) responses to take, Some(future)
    /// otherwise.
    pub async fn next(&mut self) -> Option<Item> {
        match &mut self.0 {
            TransactionInner::Immediate(item) => item.take(),

            TransactionInner::Single(opt_fut) => match opt_fut.take() {
                Some(fut) => Some(fut.await),
                None => None,
            },

            TransactionInner::PendingStream(stream_fut) => {
                let mut stream = stream_fut.await;
                let next = stream.next().await;
                self.0 = TransactionInner::Stream(stream);
                next
            }

            TransactionInner::Stream(stream) => stream.next().await,
        }
    }
}

//------------ TransactionInner ----------------------------------------------

/// Private inner details of the [`Transaction`] type.
///
/// This type exists to (a) hide the `Immediate` variant from the consumer of
/// this library as it is for internal use only and not something a
/// [`Service`] impl should return, and (b) to control the interface offered
/// to consumers of this type and avoid them having to work with the enum
/// variants directly.
enum TransactionInner<Item, Future>
where
    Future: std::future::Future<Output = Item> + Send,
{
    /// The transaction will result in a single immediate response.
    ///
    /// This variant is for internal use only when aborting Middleware
    /// processing early.
    Immediate(Option<Item>),

    /// The transaction will result in at most a single response future.
    Single(Option<Future>),

    /// The transaction will result in stream of multiple response futures.
    PendingStream(
        Pin<
            Box<
                dyn std::future::Future<Output = TransactionStream<Item>>
                    + Send,
            >,
        >,
    ),

    /// The transaction is a stream of multiple response futures.
    Stream(TransactionStream<Item>),
}

//------------ TransacationStream --------------------------------------------

/// A stream of zero or more DNS response futures relating to a single DNS request.
pub struct TransactionStream<Item> {
    stream: FuturesOrdered<Pin<Box<dyn Future<Output = Item> + Send>>>,
}

impl<Item> TransactionStream<Item> {
    /// Add a response future to a transaction stream.
    pub fn push<T: Future<Output = Item> + Send + 'static>(
        &mut self,
        fut: T,
    ) {
        self.stream.push_back(fut.boxed());
    }

    async fn next(&mut self) -> Option<Item> {
        self.stream.next().await
    }
}

impl<Item> Default for TransactionStream<Item> {
    fn default() -> Self {
        Self {
            stream: Default::default(),
        }
    }
}
