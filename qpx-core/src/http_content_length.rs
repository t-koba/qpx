//! The declared Content-Length.
//!
//! RFC 9110 section 8.6 gives the field one grammar, `Content-Length =
//! 1*DIGIT`, so the value a sender writes is one decimal. The section
//! also names the one exception a recipient has: a value that is the same
//! decimal repeated as a comma-separated list may be rejected or
//! replaced with a single instance of the decimal, because it likely
//! means an upstream processor combined a duplicate. qpx takes the
//! replacement, so its reader treats an equal-member comma list as one
//! length, and a value that names two different lengths is a conflict
//! rather than a choice.
//!
//! The member grammar, the conflict rule and the entry points have one
//! owner, and it sits in qpx-core, below every crate that reads the
//! declaration, so the HTTP stack and the IPC gateway read the field the
//! same way instead of each keeping its own interpretation.
//!
//! The owner has an entry point for a header map, one for the field's
//! values, and one for a sequence of named header values, so a site that
//! reads raw header lines reaches the owner as well and does not select
//! the field's values itself.
//!
//! The field has a sending half as well, and the owner holds it too.
//! The section's sender rule forbids forwarding a value that does not
//! match the grammar, and the section's one exception lets a recipient
//! of an equal-member comma list either reject the message or replace
//! that value with a single instance of the decimal value. qpx
//! replaces it: the owner holds the value a writer emits for a resolved
//! length, and the writers that forward a declaration write that value,
//! so the field leaves as one field line whose value is the resolved
//! decimal.
//!
//! A declaration the owner refuses names no length, so the message it
//! came in has ambiguous framing, and the tree answers each side of
//! that. A request that carries one is answered with a bad request, and
//! the HTTP/1 edge closes the connection, because a request whose length
//! cannot be determined cannot be framed. A response from an origin
//! that carries one is refused as well: the proxy answers the client
//! with a bad gateway, and the connection to the origin is closed rather
//! than reused, because the origin's framing is unknown. The reverse
//! path may try another origin first, which is a new request rather
//! than a forwarding of the response that could not be framed.
//!
//! The writers that write it are the ones this tree owns: the HTTP/1
//! request writer, the HTTP/1 raw response relay, the reverse raw
//! HTTP/1 fast path, the HTTP/1 response writers to the client, the
//! HTTP/2 request and response writers, the HTTP/3 request and response
//! writers, and the HTTP/3 library's response head sanitizer. A path
//! that hands a header map to another library's writer - the HTTP/1
//! client library - leaves that library to write the values the map
//! holds, so a declaration those paths carry is not written by qpx in
//! the canonical form.

use http::HeaderMap;
use http::HeaderValue;
use http::header::CONTENT_LENGTH;
use thiserror::Error;

/// The field's name, as a header spells it.
///
/// The name is compared case-insensitively, as HTTP requires, so a site
/// that reads raw header lines reaches the owner without selecting the
/// field's values itself.
const CONTENT_LENGTH_NAME: &[u8] = b"content-length";

/// Parses one Content-Length comma-list member per RFC 9110 §8.6
/// (`1*DIGIT`): the trimmed member must be a nonempty ASCII digit sequence,
/// then the `u64` value. Plain integer parsing would also accept a leading
/// `+` sign, which is not valid field syntax.
pub fn parse_content_length_member(part: &str) -> Option<u64> {
    let digits = part.trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()
}

/// The error a declared Content-Length carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ContentLengthError {
    /// A field value is not readable as text.
    #[error("invalid content-length header")]
    InvalidHeader,
    /// A member is not a `1*DIGIT` sequence.
    #[error("invalid content-length value")]
    InvalidValue,
    /// Two members declare different lengths.
    #[error("conflicting content-length values")]
    Conflicting,
}

/// The Content-Length that a header set declares.
///
/// The field's grammar is one decimal (RFC 9110 section 8.6), and the
/// section's one exception lets a recipient treat a value that is the
/// same decimal repeated as a comma-separated list as that decimal, so a
/// value here may hold such a list and still name one length. Two
/// different lengths are a conflict rather than a choice.
///
/// The field's sending half belongs to the owner as well: the grammar a
/// sender writes is one decimal, so the value the owner writes for a
/// resolved length is a single instance of that decimal, and a writer
/// that replaces the declaration it received with it emits one field
/// line whose value is the resolved decimal.
///
/// The owner sits beside the member grammar it uses, so the HTTP/1 and
/// HTTP/2 codecs, the HTTP/3 codec and listener, the cache, the upstream
/// raw HTTP/1 path, the reverse raw HTTP/1 path, the reverse mirror path,
/// the reverse request template, the request validation and the observed
/// body size read the field the same way instead of each keeping its own
/// interpretation.
///
/// Every site that reads the declaration through a helper of its own reads
/// it through the owner, so the Content-Length gate can check that the tree
/// and the owner agree: a site that reads the declaration through a helper
/// calls the owner unless the owner names it as a site that does something
/// different. No site does something different today, so the owner names
/// none.
///
/// The upstream raw HTTP/1 path reads the declaration through the owner as
/// well: `qpxd/src/upstream/raw_http1/mod.rs` calls it with the header map
/// it holds, and `qpxd/src/upstream/raw_http1/raw_head.rs`, which reads raw
/// header lines rather than a header map, hands the lines to the owner's
/// named-value entry point, which finds the field's own values. A leading
/// plus sign is refused there too, so an upstream response that frames its
/// body with one is rejected instead of read.
///
/// The reverse raw HTTP/1 path reads the declaration through the owner as
/// well: `qpxd/src/reverse/transport/raw_http1.rs` reads raw header lines
/// rather than a header map, so it hands the lines to the owner's
/// named-value entry point, which finds the field's own values, and the
/// length it reads says whether the request may carry a body. A leading
/// plus sign is refused there, so a request that declares its length as
/// "+0" is treated as one that may carry a body instead of one without a
/// body, and the fast path is declined for it. A comma list of equal
/// members is still one length and two members that disagree are still a
/// conflict.
///
/// The reverse mirror path reads the declaration through the owner as well:
/// `qpxd/src/reverse/transport/mirrors.rs` calls it for the length that
/// says whether a request can be mirrored. A comma list of equal members is
/// one length there now, so such a request can be mirrored, and a leading
/// plus sign is refused, so a request that declares its length that way is
/// not mirrored.
///
/// The reverse request template reads the declaration through the owner as
/// well: `qpxd/src/reverse/transport/request_template.rs` calls it for the
/// length a retry may buffer and for the length that says whether the
/// request may carry a body. A comma list of equal members is one length
/// there now, so such a request is retried within the threshold, and a
/// leading plus sign is refused, so a request that declares its length that
/// way is not retried.
///
/// The observed body size is read through the owner as well:
/// `qpxd/src/http/body/size/io.rs` hands the header map to it and reads the
/// answer as a size hint. The hint is the length the field declares, so a
/// comma list of equal members is one length there now and such a request
/// has an observed size instead of a body that is observed, a leading plus
/// sign is refused there too and gives no hint, and two values that
/// disagree declare no length, so the body of such a request is observed
/// rather than sized from the first value, which is what the plain integer
/// parse this reader used to do.
///
/// The truncated response body reads the declaration through the owner as
/// well: `qpxd/src/http/capture/stream.rs` hands the header map to it, and
/// the reverse raw HTTP/1 path calls the same helper, so one place decides
/// whether a body that is cut to the limit keeps the length it declared. A
/// comma list of equal members is one length there now, so a response that
/// declares its size that way loses the declaration when the body is cut,
/// and a declaration the owner refuses names no length, so the header stays
/// as it did when the plain integer parse could not read the value.
///
/// The subrequest module reads the declaration through the owner as well:
/// `qpxd/src/http/modules/subrequest.rs` hands the header map to it, so the
/// length that says whether the response is over the module's limit is the
/// length the field declares. A comma list of equal members is one length
/// there now, so such a response is refused instead of being cut to the
/// limit, and a declaration the owner refuses names no length, so the
/// response is cut to the limit rather than refused; the body is limited
/// either way.
///
/// The decision service reads the declaration through the owner as well:
/// `qpxd/src/policy_context/decision_service/mod.rs` hands the header map
/// to it, so the length that says whether the response is over the hard cap
/// is the length the field declares. A comma list of equal members is one
/// length there now, so such a response is refused before its body is read,
/// and a declaration the owner refuses names no length, so the body is read
/// under the cap instead; the cap holds either way.
///
/// The response compression module reads the declaration through the owner
/// as well: `qpxd/src/http/modules/response_compression.rs` hands the header
/// map to it, so the length that says whether the body is within the
/// compressible window is the length the field declares. A comma list of
/// equal members is one length there now, so such a response is compressed
/// when the window allows it, and a declaration the owner refuses names no
/// length, so the response declares no size and is not compressed.
///
/// The HTTP/3 path reads the declaration through the owner as well:
/// `qpx-h3/src/response.rs` hands the header map to it, so the HTTP/3 server
/// and client frame a body from the same length the HTTP/1 and HTTP/2 paths
/// read. A leading plus sign is refused there too, and the request and the
/// response sides treat that differently: a request that declares its
/// length that way is refused, while a response that declares it that way
/// has the field dropped rather than the response refused.
///
/// The cache reads the declaration through the owner as well:
/// `qpxd-cache/src/entry.rs` hands the stored response's named header
/// values to the owner's named-value entry point, which finds the field's
/// own values, and the test helper in `qpxd-cache/src/util.rs` hands the
/// header map to it. A leading plus sign is refused there too, so a stored
/// response that declares its length that way declares no length: the cache
/// falls back to the stored body's length, and the helper reports no
/// cacheable length.
///
/// The cache backend reads the declaration through the owner as well:
/// `qpxd-cache/src/backend_http.rs` hands the response's header map to it,
/// so the length the cache compares with its size limit and with the length
/// it expects is the length the field declares. A comma list of equal
/// members is one length there now, so a response that declares its size
/// that way is measured against the limit instead of escaping the check,
/// and a response that declares a length other than the one the cache
/// expects is a miss instead of a body that fails while it is read. The
/// shapes the owner refuses - a leading plus sign, a member that is not
/// digits, two members that disagree - do not reach that path at all: the
/// HTTP/1 client that delivers the response refuses such a response before
/// its headers arrive, so the cache's reading and the framing that
/// delivered the response cannot disagree. A response that declares no
/// length is not measured against the limit: the streaming limit bounds the
/// body instead, and the object the cache asked for is confirmed by the
/// body it reads.
///
/// The IPC gateway reads the declaration through the owner as well:
/// `qpxf/src/ipc_request.rs` hands the header list's named values to the
/// owner's named-value entry point, which finds the field's own values, so
/// the length that says how many stdin bytes the script may read is the
/// length the field declares. A leading plus sign is refused there too, so
/// a request that declares its length that way is refused instead of read,
/// and a comma list of equal members is one length there as well.
///
/// The gate finds those helpers by the names the workspace has used for
/// them, and it looks inside a function's body as well, so a site that
/// reads the declaration inline is inside the gate too: a function that
/// reads the field's value and turns text into a number reads the
/// declaration itself, and it must reach the owner alone. The gate sees
/// that number whether the parse names its type or leaves it to be
/// inferred, so a reader cannot hide behind an inferred type. No site
/// reads the declaration inline today: the response compression test,
/// the last one, reads it through the owner as well.
///
/// The gate asks a second question that does not depend on the name of a
/// helper: in the shipped code, does any site read the field's value? The
/// owner reads it and no other shipped site does, so a read of the value
/// is a violation on its own. That is what catches the readers the naming
/// rule cannot see: a site that reads the value and hands it to another
/// function, and a site whose helper carries a name the workspace has
/// never used. The gate sees the field named through a reference to the
/// constant, through the constant's text and through a name built from
/// the field's text, so a reader cannot hide behind another spelling of
/// the field's name. The gate follows a binding of the field's name as
/// well: a site that binds the field's name to a name of its own and
/// reads the field through that binding reads the declaration, so a
/// reader cannot hide behind a name the site holds of its own. The gate
/// follows a constant or a static that holds the field's name as well,
/// so a reader cannot hide behind a constant of its own either, and it
/// follows an import that gives the field's name a name of its own, so
/// a reader cannot hide behind a renamed import either. The imports of
/// a nested module are the file's imports too, so the gate reads them
/// as well; an import inside a function body is not one of them,
/// because it is a name that one function holds and not a name the file
/// holds. The name an import brings the field's name under is followed
/// for the whole file, so a nested module that uses that name for
/// something else is read as a reader of the declaration; the gate errs
/// towards seeing a read. A constant of
/// another file of the workspace that holds the field's name is
/// followed as well, and the import that brings such a constant in is
/// read the way the field's own imports are read, so an import in a
/// nested module is followed too: the gate reads the constants of the
/// workspace's files, so a site that imports such a constant holds the
/// field's name under the name the import gives it, and the import may
/// rename it.
/// The gate matches that constant by its name and not by the path the
/// import takes, so a constant of a crate outside the workspace is not
/// followed, a name one file holds the field's name under and another
/// file holds another value under is not followed either, and a
/// constant an import reaches through a glob is not followed. The gate
/// sees a value taken out of the field's own
/// entry as well: a site that compares a header's name with the field's
/// name and takes the value of a header entry in the same body finds that
/// entry itself, which is the second reading of the field this owner
/// removes, so the cache hands the owner the stored response's named
/// values rather than selecting the field's values on its own. The gate
/// sees the value however it is taken out of the entry: by a closure
/// that receives the entry as a pair, by the second element of the pair,
/// by the `value` member of the entry whose name the comparison found,
/// and by a pattern that binds the entry's pair, where the name the
/// pattern bound is the name the comparison uses and the value the
/// pattern bound is the value that is taken. The gate follows the member
/// the value is held under as well: a header entry holds its name and
/// its value under members of its own, so a site that finds the field's
/// own entry and takes a member of it that is not the member holding the
/// name reads the declaration's value, and a reader cannot hide behind a
/// member the gate has not seen. The member the comparison used is the
/// name, so a site that takes that member takes the name and not the
/// value. The value is the field's
/// value when the site selects the field's own entry, and a comparison
/// of a header's name with the field's name is what selects it. A
/// comparison that decides about the field instead does not select it: a
/// comparison whose branch skips the entry decides about the field, so a
/// site that skips the field and takes another header's value is not a
/// reader. A comparison that is not equal reads the other way round when
/// the branch skips the entry, because the entry that reaches the code
/// after the branch is the field's own. A comparison that stands in a
/// condition that holds more than the comparison is not read as deciding
/// about the field at all: the gate cannot say which part of the
/// condition skips the entry, so the comparison finds the field's own
/// entry, and the code after the branch may hold it. The value has to
/// come from the entry the comparison found: the gate reads a member of
/// the entry only when the site takes it under the name it compared or
/// under a name the entry travels to, so a site that compares the
/// field's name and takes another entry's value is not a reader
/// either. The gate follows the entry as it travels: a binding of the
/// entry holds it under a name of its own, a closure that receives it
/// from the search that found it holds it under the name the closure
/// binds, a pattern that binds the search's result holds it as well,
/// and a helper that found it hands it to its caller, which binds the
/// result, so the value the site takes under any of those names is the
/// field's value. A caller that takes the value out of the result the
/// helper hands it reads the value as well, whether it destructures the
/// pair or a closure receives it. The helper may stand in another
/// file, because the gate reads the files of the workspace together.
/// The gate follows a
/// binding of a header entry's name as well: a site that binds the
/// entry's name to a name of its own and compares that name with the
/// field's name compares the entry's name, so the binding stands for
/// the entry the name came from and the value the site takes is that
/// entry's value.
/// The gate follows a copy of a name as well: a site that copies the
/// name of the entry it holds holds that entry's name, so the
/// comparison under the copy finds that entry and the value the site
/// takes is that entry's value, and a site that copies the field's own
/// name holds the field's name, so a read through that copy reads the
/// declaration. A copy of a name the site holds is that name, so a copy
/// of a binding of the field's name and a copy of a constant the site
/// keeps the field's name in name the field as well.
/// The gate follows a name the site builds at runtime as well: a site
/// that builds the field's name with a constructor or with a macro and
/// finds the field's own entry with the built name reads the
/// declaration, so the gate reads the text the site writes out and
/// follows it back to the field. The text the site writes out may stand
/// under a name of its own, so the gate reads the text a binding holds
/// as well and follows a name the site builds from that piece, whether
/// the site builds it with a macro that takes the piece by its name or
/// by adding the piece to another piece. A name the site builds at
/// runtime from text the site did not write out is a name the gate
/// cannot follow.
/// Test code is not
/// part of that question, because a test observes the value to assert on
/// what the proxy put on the wire rather than to decide what the proxy
/// does; a test that reads the value and turns it into a number is still
/// inside the gate.
///
/// The test helpers read the declaration through the owner as well:
/// `qpxd/src/test_util.rs` and `qpxd/tests/http_rfc/mod.rs` read a raw
/// head rather than a header map, so they hand the head's lines to the
/// owner's named-value entry point, which finds the field's own values. A
/// comma list of equal members is one length there now, so such a head
/// declares the length of the body it carries, and a declaration the owner
/// refuses names no length, so the helper reads no body.
///
/// The response compression test reads the declaration through the owner as
/// well: `qpxd/src/http/modules/response_compression/tests.rs` hands the
/// header map to it, so the length the test compares with the body's own
/// length is the length the field declares. A comma list of equal members
/// is one length there now, so such a response declares the length of the
/// body it carries, and a declaration the owner refuses names no length,
/// so the test sees no length to compare.
///
/// The access log reads the declaration through the owner as well:
/// `qpxd/src/reverse/listener/raw_http1.rs` and
/// `qpx-observability/src/access_log.rs` hand the header map to it, so the
/// byte count the log records is the length the field declares. A comma
/// list of equal members is one length there now, so the count is that
/// length instead of no bytes, and a declaration the owner refuses names no
/// length, so the count is no bytes.
///
/// The request guard reads the declaration through the owner as well:
/// `qpxd/src/http/policy/guard.rs` hands the header map to it, so the
/// guard judges a request's framing by the length the field declares and
/// not by the text of its values. A comma list of equal members is one
/// length there now, so two values that declare the same length are no
/// longer refused as a conflict, which is the reading RFC 9112 section
/// 6.3 allows a recipient to take of duplicated values. Two values that
/// disagree are a conflict, so such a request is refused as one, and so is
/// one value that names two lengths. A declaration the owner refuses - a
/// member that is not digits, a leading plus sign, a value that is not
/// text - is refused as well, because a request whose length cannot be
/// determined has ambiguous framing.
pub fn declared_content_length(headers: &HeaderMap) -> Result<Option<u64>, ContentLengthError> {
    // Every value is read as text before any member is parsed, so a field
    // that carries a value which is not text is reported the same way
    // whatever else the field carries.
    for value in headers.get_all(CONTENT_LENGTH) {
        value
            .to_str()
            .map_err(|_| ContentLengthError::InvalidHeader)?;
    }
    let mut declared = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let value = value
            .to_str()
            .map_err(|_| ContentLengthError::InvalidHeader)?;
        merge_value(value, &mut declared)?;
    }
    Ok(declared)
}

/// Merges one field value's members into the length the field declares so
/// far.
///
/// Every member of the value declares the same length, so a value that
/// names two different lengths is a conflict rather than a choice.
fn merge_value(value: &str, declared: &mut Option<u64>) -> Result<(), ContentLengthError> {
    for part in value.split(',') {
        let length = parse_content_length_member(part).ok_or(ContentLengthError::InvalidValue)?;
        if let Some(previous) = *declared
            && previous != length
        {
            return Err(ContentLengthError::Conflicting);
        }
        *declared = Some(length);
    }
    Ok(())
}

/// The Content-Length that a sequence of field values declares.
///
/// The values are the field's values in the order they appear. The
/// field's grammar is one decimal (RFC 9110 section 8.6), and the
/// section's one exception lets a recipient treat a value that is the
/// same decimal repeated as a comma-separated list as that decimal, so a
/// value here may hold such a list and still name one length. Two
/// different lengths are a conflict rather than a choice.
///
/// The field's sending half belongs to the owner as well: the grammar a
/// sender writes is one decimal, so the value the owner writes for a
/// resolved length is a single instance of that decimal, and a writer
/// that replaces the declaration it received with it emits one field
/// line whose value is the resolved decimal.
///
/// A site that reads the declaration from raw header lines has no header
/// map to hand the owner, so it hands the values instead: the member
/// grammar and the conflict rule stay in one place.
pub fn declared_content_length_in_values<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<Option<u64>, ContentLengthError> {
    let mut declared = None::<u64>;
    for value in values {
        merge_value(value, &mut declared)?;
    }
    Ok(declared)
}

/// The Content-Length that a sequence of named header values declares.
///
/// The field's sending half belongs to the owner as well: the grammar a
/// sender writes is one decimal, so the value the owner writes for a
/// resolved length is a single instance of that decimal, and a writer
/// that replaces the declaration it received with it emits one field
/// line whose value is the resolved decimal.
///
/// A site that reads raw header lines has no header map to hand the
/// owner, so it hands the lines themselves: the owner finds the field's
/// own values by their name, matched case-insensitively as HTTP requires,
/// and reads them with the same member grammar and the same conflict rule
/// as every other reader. A site that selected the field's values itself
/// kept a second reading of the field, which is the shape this owner
/// removes.
///
/// The names and the values are borrowed as bytes, so a site whose lines
/// are raw bytes and a site whose lines are text reach the owner without
/// copying them.
///
/// A value that is not text is refused before a conflict is reported, even
/// when the conflict is in an earlier value: the values are read as text
/// first and the members are merged afterwards, so the first value that
/// cannot be read is the error. The value-level entry point merges as it
/// goes and stops at the first member it cannot read, and it cannot be
/// given a value that is not text at all, so the two entry points report
/// the same error wherever both of them can report one.
pub fn declared_content_length_in_named_values<'a, N, V>(
    headers: impl IntoIterator<Item = (&'a N, &'a V)>,
) -> Result<Option<u64>, ContentLengthError>
where
    N: AsRef<[u8]> + ?Sized + 'a,
    V: AsRef<[u8]> + ?Sized + 'a,
{
    let mut declared = None::<u64>;
    let mut merge_error = None;
    for (name, value) in headers {
        let name: &[u8] = name.as_ref();
        if !name.eq_ignore_ascii_case(CONTENT_LENGTH_NAME) {
            continue;
        }
        let value: &[u8] = value.as_ref();
        let value = std::str::from_utf8(value).map_err(|_| ContentLengthError::InvalidHeader)?;
        if merge_error.is_none()
            && let Err(error) = merge_value(value, &mut declared)
        {
            merge_error = Some(error);
        }
    }
    match merge_error {
        Some(error) => Err(error),
        None => Ok(declared),
    }
}

/// The canonical field value for a resolved length.
///
/// RFC 9110 section 8.6 gives the field the grammar `1*DIGIT`, so the
/// value a sender writes is one decimal and nothing else. The same
/// section's sender rule forbids forwarding a value that does not match
/// that grammar, and the section's one exception lets a recipient of an
/// equal-member comma list either reject the message or replace that
/// value with a single instance of the decimal value. qpx replaces it,
/// so a writer emits one field line whose value is the resolved decimal.
///
/// The value belongs to the owner, so a writer does not format the
/// decimal itself: a writer that has resolved a length asks the owner
/// for the value of that length and writes what the owner gives it.
pub fn canonical_content_length_value(length: u64) -> HeaderValue {
    HeaderValue::from(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn canonical_content_length_value_writes_one_decimal() {
        // The value a sender writes is one decimal, so the owner writes
        // the resolved length as that decimal and nothing else.
        assert_eq!(
            canonical_content_length_value(42).to_str().expect("text"),
            "42"
        );
        assert_eq!(
            canonical_content_length_value(0).to_str().expect("text"),
            "0"
        );
        assert_eq!(
            canonical_content_length_value(u64::MAX)
                .to_str()
                .expect("text"),
            "18446744073709551615"
        );
    }

    #[test]
    fn declared_content_length_reads_every_member_of_every_value() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42, 42"));
        assert_eq!(declared_content_length(&headers), Ok(Some(42)));
    }

    #[test]
    fn declared_content_length_in_values_reads_every_member_of_every_value() {
        assert_eq!(
            declared_content_length_in_values(["42", "42, 42"]),
            Ok(Some(42))
        );
        assert_eq!(
            declared_content_length_in_values(Vec::<&str>::new()),
            Ok(None)
        );
    }

    #[test]
    fn declared_content_length_in_values_rejects_a_member_that_is_not_digits() {
        for values in [
            vec!["+5"],
            vec!["5, +5"],
            vec![""],
            vec!["4,"],
            vec!["4,,4"],
        ] {
            assert_eq!(
                declared_content_length_in_values(values),
                Err(ContentLengthError::InvalidValue)
            );
        }
    }

    #[test]
    fn declared_content_length_in_named_values_reads_the_field_by_its_name() {
        assert_eq!(
            declared_content_length_in_named_values([
                ("Content-Type", "text/plain"),
                ("Content-Length", "42"),
                ("content-length", "42, 42"),
            ]),
            Ok(Some(42))
        );
    }

    #[test]
    fn declared_content_length_in_named_values_ignores_the_other_fields() {
        assert_eq!(
            declared_content_length_in_named_values([("Content-Type", "text/plain")]),
            Ok(None)
        );
    }

    #[test]
    fn declared_content_length_in_named_values_reads_raw_bytes() {
        assert_eq!(
            declared_content_length_in_named_values([
                (&b"Content-Length"[..], &b"42"[..]),
                (&b"content-length"[..], &b"42"[..]),
            ]),
            Ok(Some(42))
        );
    }

    #[test]
    fn declared_content_length_in_named_values_rejects_a_value_that_is_not_text() {
        assert_eq!(
            declared_content_length_in_named_values([(&b"Content-Length"[..], &[0xff][..])]),
            Err(ContentLengthError::InvalidHeader)
        );
    }

    #[test]
    fn declared_content_length_in_named_values_rejects_conflicting_members() {
        assert_eq!(
            declared_content_length_in_named_values([
                ("Content-Length", "5"),
                ("content-length", "6"),
            ]),
            Err(ContentLengthError::Conflicting)
        );
    }

    #[test]
    fn declared_content_length_in_named_values_reports_a_value_that_is_not_text_first() {
        // A value that cannot be read is the error even when an earlier
        // value names two different lengths: the value that is not text is
        // refused before the conflict is reported.
        assert_eq!(
            declared_content_length_in_named_values([
                (&b"Content-Length"[..], &b"5, 6"[..]),
                (&b"content-length"[..], &[0xff][..]),
            ]),
            Err(ContentLengthError::InvalidHeader)
        );
    }

    #[test]
    fn the_entry_points_report_the_same_error_where_they_can_both_report_one() {
        // The record says the two entry points report the same error
        // wherever both of them can report one, so the same field is read
        // through each of them and the answers are compared.
        for values in [
            &["5"][..],
            &["5, 5"][..],
            &["5, 6"][..],
            &["x"][..],
            &["x", "5, 6"][..],
            &["5, 6", "x"][..],
            &["+5"][..],
        ] {
            let mut headers = HeaderMap::new();
            let mut named = Vec::new();
            for value in values.iter().copied() {
                headers.append(CONTENT_LENGTH, HeaderValue::from_static(value));
                named.push((&b"content-length"[..], value.as_bytes()));
            }
            let by_value = declared_content_length_in_values(values.iter().copied());
            let by_name = declared_content_length_in_named_values(named.clone());
            assert_eq!(by_name, by_value, "{values:?}");
            assert_eq!(declared_content_length(&headers), by_name, "{values:?}");
        }
    }

    #[test]
    fn declared_content_length_in_values_reports_a_conflict_before_a_later_invalid_member() {
        // The value-level entry point merges as it goes, so it stops at
        // the first member it cannot read: a conflict in an earlier value
        // is reported before a later value's invalid member.
        assert_eq!(
            declared_content_length_in_values(["5, 6", "+5"]),
            Err(ContentLengthError::Conflicting)
        );
    }

    #[test]
    fn declared_content_length_in_values_rejects_conflicting_members() {
        assert_eq!(
            declared_content_length_in_values(["5", "6"]),
            Err(ContentLengthError::Conflicting)
        );
    }

    #[test]
    fn declared_content_length_rejects_a_member_that_is_not_digits() {
        for value in ["+5", "-5", "5x", "", "4,", "4,,4"] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_LENGTH, HeaderValue::from_static(value));
            assert_eq!(
                declared_content_length(&headers),
                Err(ContentLengthError::InvalidValue),
                "{value}"
            );
        }
    }

    #[test]
    fn declared_content_length_rejects_two_different_lengths() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("5"));
        assert_eq!(
            declared_content_length(&headers),
            Err(ContentLengthError::Conflicting)
        );

        let mut one_value = HeaderMap::new();
        one_value.insert(CONTENT_LENGTH, HeaderValue::from_static("4, 5"));
        assert_eq!(
            declared_content_length(&one_value),
            Err(ContentLengthError::Conflicting)
        );
    }

    #[test]
    fn declared_content_length_rejects_a_value_that_is_not_text() {
        let mut headers = HeaderMap::new();
        headers.append(
            CONTENT_LENGTH,
            HeaderValue::from_bytes(b"\xff").expect("opaque value"),
        );
        assert_eq!(
            declared_content_length(&headers),
            Err(ContentLengthError::InvalidHeader)
        );
    }
}
