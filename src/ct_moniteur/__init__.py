"""
Certificate Transparency Log Monitor Library
Supports both classic and tiled CT logs with async operations and state persistence.
"""

import asyncio
import base64
import hashlib
import inspect
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Union, cast

import httpx2
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .binary_reader import BinaryReader, DataType, Endianness
from .httpx_ratelimit import RateLimitedTransport
from .itertools_compat import batched

__version__ = "1.0.0"

# Create module logger
logger = logging.getLogger(__name__)
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"


def _validate_user_agent(user_agent: str) -> None:
    """Require contact info, as some tiled logs rate-limit anonymous clients."""
    if not any(marker in user_agent for marker in ("@", "https://", "github.com/")):
        raise ValueError(
            "User-Agent must include contact info: an email address, an HTTPS URL "
            "or a github.com/ link"
        )


class EntryType(IntEnum):
    """CT log entry types"""

    X509_ENTRY = 0
    PRECERT_ENTRY = 1


@dataclass
class TiledCheckpoint:
    """Checkpoint information from a tiled CT log"""

    origin: str
    size: int
    hash: str


@dataclass
class SignedTreeHead:
    """Signed Tree Head from a classic CT log"""

    tree_size: int
    timestamp: int
    sha256_root_hash: str
    tree_head_signature: str


@dataclass
class LogEntry:
    """Single entry from a CT log"""

    timestamp: int
    entry_type: EntryType
    entry: bytes
    chain: List[bytes] = field(default_factory=list)


@dataclass
class LogMeta:
    """Metadata about a CT log"""

    url: str
    name: str
    operator: str


@dataclass
class EntrySource:
    """Source information for a certificate entry"""

    index: int
    log: LogMeta


@dataclass
class CertificateEntry:
    """Parsed certificate entry"""

    timestamp: int
    entry_type: str  # "X509LogEntry" or "PrecertLogEntry"
    certificate: x509.Certificate
    source: EntrySource

    # Certificate details
    domains: List[str] = field(default_factory=list)
    subject: str = ""
    issuer: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: str = ""
    fingerprint_sha256: str = ""
    fingerprint_sha1: str = ""


@dataclass
class MoniteurStats:
    """Statistics for monitoring"""

    total_entries_processed: int = 0
    entries_per_log: Dict[str, int] = field(default_factory=dict)
    errors_per_log: Dict[str, int] = field(default_factory=dict)
    active_logs: int = 0
    start_time: Optional[datetime] = None


class TiledLogClient:
    """Client for interacting with tiled CT logs"""

    DEFAULT_USER_AGENT = f"CT-Moniteur/{__version__} (github.com/CERT-Polska/ct-moniteur)"
    TILE_SIZE = 256

    def __init__(
        self,
        log_meta: LogMeta,
        timeout: float = 30.0,
        user_agent: Optional[str] = None,
        transport: Optional[httpx2.AsyncBaseTransport] = None,
    ):
        if user_agent:
            _validate_user_agent(user_agent)

        self.log_meta = log_meta
        self.timeout = timeout
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self._client = httpx2.AsyncClient(
            base_url=log_meta.url,
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            transport=transport or RateLimitedTransport(),
        )

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def close(self):
        """Close the HTTP client"""
        await self._client.aclose()

    async def fetch_checkpoint(self) -> TiledCheckpoint:
        """Fetch the checkpoint from a tiled CT log"""
        response = await self._client.get("/checkpoint")
        response.raise_for_status()

        lines = response.text.strip().split("\n")
        if len(lines) < 3:
            raise ValueError(
                f"Invalid checkpoint format: expected at least 3 lines, got {len(lines)}"
            )

        return TiledCheckpoint(origin=lines[0], size=int(lines[1]), hash=lines[2])

    async def fetch_tree_size(self) -> int:
        """Fetch the current tree size (number of entries in the log)"""
        checkpoint = await self.fetch_checkpoint()
        return checkpoint.size

    async def fetch_tile(
        self, tile_index: int, partial_width: Optional[int] = None
    ) -> List[LogEntry]:
        """
        Fetch a tile from the tiled CT log

        Args:
            tile_index: The index of the tile to fetch
            partial_width: If specified, fetch a partial tile with this width (1-255)
        """
        tile_path = self._encode_tile_path(tile_index)

        # Add partial tile suffix if specified
        if partial_width is not None:
            if not (1 <= partial_width <= 255):
                raise ValueError(
                    f"Partial tile width must be between 1 and 255, got {partial_width}"
                )
            tile_path = f"{tile_path}.p/{partial_width}"

        response = await self._client.get(f"/tile/data/{tile_path}")
        response.raise_for_status()

        return self._parse_tile_data(response.content)

    async def fetch_issuer(self, fingerprint: bytes) -> bytes:
        """
        Fetch an issuer certificate by its SHA-256 fingerprint.

        Args:
            fingerprint: 32-byte SHA-256 hash of the ASN.1 encoding of the issuer certificate

        Returns:
            ASN.1-encoded issuer certificate bytes
        """
        # Convert fingerprint bytes to lowercase hex string
        fingerprint_hex = fingerprint.hex().lower()

        response = await self._client.get(f"/issuer/{fingerprint_hex}")
        response.raise_for_status()

        return response.content

    @staticmethod
    def _encode_tile_path(index: int) -> str:
        """
        Encode a tile index into the proper path format.
        Example: 1234567 -> x001/x234/567
        """
        if index == 0:
            return "000"

        groups = []
        n = index
        while n > 0:
            groups.append(n % 1000)
            n //= 1000

        groups.reverse()

        parts = [f"x{g:03d}" for g in groups[:-1]] + [f"{groups[-1]:03d}"]
        return "/".join(parts)

    def _parse_tile_data(self, data: bytes) -> List[LogEntry]:
        """Parse binary tile data into LogEntry entries"""
        reader = BinaryReader(data, Endianness.BIG)
        leaves: List[LogEntry] = []

        while reader.remaining >= 10:  # Minimum header size
            # Read timestamp (8 bytes) and entry_type (2 bytes)
            timestamp = reader.read(DataType.UINT, 8)
            entry_type = reader.read(DataType.UINT, 2)

            entry_data: bytes
            chain: List[bytes] = []

            if entry_type == EntryType.X509_ENTRY:
                # Read certificate (3-byte length)
                if not reader.has_bytes(3):
                    break
                cert_len = reader.read(DataType.UINT, 3)

                if not reader.has_bytes(cert_len):
                    break
                entry_data = reader.read(DataType.BYTES, cert_len)

                # Read extensions (skip)
                if not reader.has_bytes(2):
                    break
                ext_len = reader.read(DataType.UINT, 2)
                if not reader.has_bytes(ext_len):
                    break
                reader.skip(ext_len)

            elif entry_type == EntryType.PRECERT_ENTRY:
                # Skip issuer key hash
                if not reader.has_bytes(32):
                    break
                reader.skip(32)

                # Read TBSCertificate length and skip it
                if not reader.has_bytes(3):
                    break
                tbs_len = reader.read(DataType.UINT, 3)

                if not reader.has_bytes(tbs_len):
                    break
                reader.skip(tbs_len)

                # Read extensions (skip)
                if not reader.has_bytes(2):
                    break
                ext_len = reader.read(DataType.UINT, 2)
                if not reader.has_bytes(ext_len):
                    break
                reader.skip(ext_len)

                # Read the pre_certificate from LogEntry
                if not reader.has_bytes(3):
                    break
                cert_len = reader.read(DataType.UINT, 3)

                if not reader.has_bytes(cert_len):
                    break
                entry_data = reader.read(DataType.BYTES, cert_len)

            else:
                raise ValueError(f"Unknown entry type: {entry_type}")

            # Read fingerprints
            if not reader.has_bytes(2):
                break
            fp_len = reader.read(DataType.UINT, 2)

            if not reader.has_bytes(fp_len):
                break

            # Parse fingerprints (32 bytes each)
            fp_count = fp_len // 32
            for _ in range(fp_count):
                if reader.has_bytes(32):
                    fingerprint = reader.read(DataType.BYTES, 32)
                    chain.append(fingerprint)

            leaf = LogEntry(
                timestamp=timestamp,
                entry_type=EntryType(entry_type),
                entry=entry_data,
                chain=chain,
            )
            leaves.append(leaf)

        return leaves

    async def fetch_entries_raw(
        self,
        start_index: int,
        allow_partial: bool = True,
    ) -> AsyncIterator[tuple[int, LogEntry]]:
        """
        Fetch new entries from the tiled log since the given index (raw version).

        Args:
            start_index: Index of first entry to retrieve (inclusive)
            allow_partial: Whether to fetch the trailing partial tile. If False,
                only entries in full tiles are returned.

        Yields:
            Tuples of (entry_index, LogEntry) for new entries (unparsed)
        """
        checkpoint = await self.fetch_checkpoint()
        current_size = checkpoint.size

        if current_size <= start_index:
            return

        start_tile = start_index // self.TILE_SIZE
        end_tile = current_size // self.TILE_SIZE

        # Process complete tiles
        for tile_idx in range(start_tile, end_tile):
            try:
                leaves = await self.fetch_tile(tile_idx)
            except httpx2.HTTPStatusError as e:
                if e.response.status_code != 404:
                    raise
                logger.warning(f"Tile {tile_idx} not yet available from {self.log_meta.url}")
                return

            for i, leaf in enumerate(leaves):
                entry_index = tile_idx * self.TILE_SIZE + i

                if entry_index < start_index:
                    continue

                yield entry_index, leaf

        # Process partial tile if exists
        partial_size = current_size % self.TILE_SIZE
        if allow_partial and partial_size > 0 and end_tile * self.TILE_SIZE < current_size:
            try:
                leaves = await self.fetch_tile(end_tile, partial_width=partial_size)
            except httpx2.HTTPStatusError as e:
                if e.response.status_code != 404:
                    raise
                logger.warning(f"Tile {end_tile} not yet available from {self.log_meta.url}")
                return

            for i, leaf in enumerate(leaves):
                entry_index = end_tile * self.TILE_SIZE + i

                if entry_index < start_index:
                    continue

                if entry_index >= current_size:
                    break

                yield entry_index, leaf

    async def fetch_entries(
        self,
        start_index: int,
        allow_partial: bool = True,
    ) -> AsyncIterator[CertificateEntry]:
        """
        Fetch new entries from the tiled log since the given index.

        Args:
            start_index: Index of first entry to retrieve (inclusive)
            allow_partial: Whether to fetch the trailing partial tile. If False,
                only entries in full tiles are returned.

        Yields:
            CertificateEntry objects for new entries
        """
        async for entry_index, leaf in self.fetch_entries_raw(start_index, allow_partial):
            try:
                source = EntrySource(index=entry_index, log=self.log_meta)
                entry = CertificateParser.parse_log_entry(leaf, source)
                yield entry
            except Exception as e:
                logger.warning(
                    f"Error parsing tiled entry {entry_index} from {self.log_meta.url}: {e}"
                )

    async def watch(
        self,
        start_index: Optional[int] = None,
        poll_interval: float = 30,
    ) -> AsyncIterator[CertificateEntry]:
        """
        Continuously watch the log for new entries.

        Args:
            start_index: Index to start from. If None, starts from current tree size
            poll_interval: How often to poll for new entries (seconds)

        Yields:
            CertificateEntry objects as they are discovered

        Example:
            async with TiledLogClient(url, name, operator) as client:
                async for entry in client.watch():
                    print(entry.domains)

        To avoid repeatedly downloading the same partial tile, the trailing
        partial tile is only fetched when the previous poll returned no entries.
        On slow logs this can delay new entries by up to one poll interval.
        """
        current_index = start_index
        if current_index is None:
            current_index = await self.fetch_tree_size() - 1
            await asyncio.sleep(poll_interval)

        allow_partial = False
        lag: float = 0
        while True:
            loop = asyncio.get_running_loop()
            cycle_start = loop.time()

            got_entries = False
            async for entry in self.fetch_entries(current_index + 1, allow_partial):
                current_index = entry.source.index
                got_entries = True
                yield entry

            allow_partial = not got_entries

            # Sleep for the remaining time in the poll interval
            remaining_time = poll_interval - (loop.time() - cycle_start)

            if remaining_time > 0:
                await asyncio.sleep(remaining_time)
                lag = 0
            else:
                current_lag = -remaining_time
                if current_lag > lag:
                    logger.warning(
                        f"Poll cycle for {self.log_meta.url} exceeded interval by {current_lag:.2f}s"
                    )
                lag = current_lag


class ClassicLogClient:
    """Client for interacting with classic CT logs"""

    DEFAULT_USER_AGENT = f"CT-Moniteur/{__version__} (github.com/CERT-Polska/ct-moniteur)"
    ENTRIES_PER_BATCH = 256

    def __init__(
        self,
        log_meta: LogMeta,
        timeout: float = 30.0,
        user_agent: Optional[str] = None,
        transport: Optional[httpx2.AsyncBaseTransport] = None,
    ):
        self.log_meta = log_meta
        self.timeout = timeout
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self._page_size: Optional[int] = None
        self._client = httpx2.AsyncClient(
            base_url=log_meta.url,
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            transport=transport or RateLimitedTransport(),
        )

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    async def close(self):
        """Close the HTTP client"""
        await self._client.aclose()

    async def get_sth(self) -> SignedTreeHead:
        """Get Signed Tree Head"""
        response = await self._client.get("/ct/v1/get-sth")
        response.raise_for_status()
        data = cast(Dict[str, Any], response.json())
        return SignedTreeHead(**data)

    async def fetch_tree_size(self) -> int:
        """Fetch the current tree size (number of entries in the log)"""
        sth = await self.get_sth()
        return sth.tree_size

    async def get_entries(self, start: int, end: int) -> List[LogEntry]:
        """Get entries from the log"""
        params = {"start": start, "end": end}
        response = await self._client.get("/ct/v1/get-entries", params=params)
        response.raise_for_status()
        data = cast(Dict[str, Any], response.json())
        raw_entries = cast(List[Dict[str, str]], data.get("entries", []))
        return self._parse_classic_entries(raw_entries)

    def _parse_classic_entries(self, raw_entries: List[Dict[str, str]]) -> List[LogEntry]:
        """Parse classic CT log entries into LogEntry objects"""
        log_entries: List[LogEntry] = []

        for entry_data in raw_entries:
            try:
                leaf_input = base64.b64decode(entry_data["leaf_input"])

                # Parse the MerkleTreeLeaf structure
                # Format: version(1) + leaf_type(1) + timestamp(8) + entry_type(2) + ...
                reader = BinaryReader(leaf_input, Endianness.BIG)

                # Validate version (must be 0 for v1)
                version = reader.read(DataType.UINT, 1)
                if version != 0:
                    raise ValueError(f"Invalid MerkleTreeLeaf version: {version}")

                # Validate leaf_type (must be 0 for timestamped_entry)
                leaf_type = reader.read(DataType.UINT, 1)
                if leaf_type != 0:
                    raise ValueError(f"Invalid leaf_type: {leaf_type}")

                timestamp = reader.read(DataType.UINT, 8)
                entry_type_val = reader.read(DataType.UINT, 2)

                chain: List[bytes] = []

                # For X509Entry: certificate is in leaf_input after the header
                # For PrecertEntry: certificate is in extra_data (PreCertEntry.LeafCert)
                if entry_type_val == 0:  # X509Entry
                    # Format: entry_type(2) + cert_length(3) + cert_data + extensions...
                    cert_len = reader.read(DataType.UINT, 3)
                    cert_data = reader.read(DataType.BYTES, cert_len)

                    # Parse chain from extra_data
                    if "extra_data" in entry_data:
                        extra_data = base64.b64decode(entry_data["extra_data"])
                        chain = self._parse_certificate_chain(extra_data)

                elif entry_type_val == 1:  # PrecertEntry
                    # For precerts, extra_data contains PreCertEntry:
                    # - LeafCert (3-byte length + cert data) - the actual precertificate
                    extra_data = base64.b64decode(entry_data["extra_data"])
                    extra_reader = BinaryReader(extra_data, Endianness.BIG)

                    # Read the LeafCert (the precertificate)
                    cert_len = extra_reader.read(DataType.UINT, 3)
                    cert_data = extra_reader.read(DataType.BYTES, cert_len)

                    # Parse chain from remaining data in extra_reader
                    remaining_data = extra_reader.read(DataType.BYTES, extra_reader.remaining)
                    chain = self._parse_certificate_chain(remaining_data)

                else:
                    raise ValueError(f"Unknown entry type: {entry_type_val}")

                log_entry = LogEntry(
                    timestamp=timestamp,
                    entry_type=EntryType(entry_type_val),
                    entry=cert_data,
                    chain=chain,
                )
                log_entries.append(log_entry)

            except Exception as e:
                logger.warning(f"Error parsing classic entry from {self.log_meta.url}: {e}")
                continue

        return log_entries

    def _parse_certificate_chain(self, chain_data: bytes) -> List[bytes]:
        """
        Parse a certificate chain from binary data.

        Format: repeated sequence of (3-byte length + certificate data)

        Args:
            chain_data: Binary data containing the certificate chain

        Returns:
            List of certificate data as bytes
        """
        chain: List[bytes] = []

        if not chain_data:
            return chain

        reader = BinaryReader(chain_data, Endianness.BIG)

        while reader.remaining >= 3:
            # Read certificate length (3 bytes)
            cert_len = reader.read(DataType.UINT, 3)

            # Check if we have enough bytes for the certificate
            if not reader.has_bytes(cert_len):
                break

            # Read certificate data
            cert_data = reader.read(DataType.BYTES, cert_len)
            chain.append(cert_data)

        return chain

    async def fetch_entries_raw(
        self,
        start_index: int,
        allow_partial: bool = True,
    ) -> AsyncIterator[tuple[int, LogEntry]]:
        """
        Fetch new entries from the classic log since the given index (raw version).

        Args:
            start_index: Index of first entry to retrieve (inclusive)
            allow_partial: Whether to fetch the trailing partial page. If False,
                only entries in full pages are returned.

        Yields:
            Tuples of (entry_index, LogEntry) for new entries (unparsed)
        """
        sth = await self.get_sth()
        tree_size = sth.tree_size

        if self._page_size is None and tree_size > 1024:
            # Logs return at most a fixed number of entries per request, a power of two
            page_size = len(await self.get_entries(0, 1023))
            if page_size < 256:
                # Some logs return 256 entries only for requests of exactly 256 aligned entries
                page_size = len(await self.get_entries(0, 255))
            if page_size.bit_count() != 1:
                logger.warning(
                    f"Page size {page_size} from {self.log_meta.url} is not a power of two"
                )
                page_size = 0
            self._page_size = page_size

        if not allow_partial and self._page_size:
            tree_size -= tree_size % self._page_size

        if tree_size <= start_index:
            return

        current_start = start_index
        if self._page_size:
            # Start at the page boundary
            current_start -= current_start % self._page_size
        step = self._page_size or tree_size
        concurrency = max(self.ENTRIES_PER_BATCH // step, 1)
        while current_start < tree_size:
            starts = range(current_start, tree_size, step)
            for batch in batched(starts, concurrency):
                results = await asyncio.gather(
                    *(self.get_entries(start, min(start + step, tree_size) - 1) for start in batch),
                    return_exceptions=True,
                )

                for start, entries in zip(batch, results):
                    if start != current_start:
                        break
                    if isinstance(entries, BaseException):
                        raise entries
                    if not entries:
                        return

                    for i, log_entry in enumerate(entries):
                        if start + i >= start_index:
                            yield start + i, log_entry

                    current_start += len(entries)

                if current_start != batch[-1] + step:
                    # A response was shorter than requested, continue from where it ended
                    break

    async def fetch_entries(
        self,
        start_index: int,
        allow_partial: bool = True,
    ) -> AsyncIterator[CertificateEntry]:
        """
        Fetch new entries from the classic log since the given index.

        Args:
            start_index: Index of first entry to retrieve (inclusive)
            allow_partial: Whether to fetch the trailing partial page. If False,
                only entries in full pages are returned.

        Yields:
            CertificateEntry objects for new entries
        """
        async for entry_index, log_entry in self.fetch_entries_raw(start_index, allow_partial):
            try:
                source = EntrySource(index=entry_index, log=self.log_meta)
                entry = CertificateParser.parse_log_entry(log_entry, source)
                yield entry
            except Exception as e:
                logger.warning(
                    f"Error parsing classic entry {entry_index} from {self.log_meta.url}: {e}"
                )

    async def watch(
        self,
        start_index: Optional[int] = None,
        poll_interval: float = 30,
    ) -> AsyncIterator[CertificateEntry]:
        """
        Continuously watch the log for new entries.

        Args:
            start_index: Index to start from. If None, starts from current tree size
            poll_interval: How often to poll for new entries (seconds)

        Yields:
            CertificateEntry objects as they are discovered

        Example:
            async with ClassicLogClient(url, name, operator) as client:
                async for entry in client.watch():
                    print(entry.domains)

        To keep requests aligned to pages, the trailing partial page is only
        fetched when the previous poll returned no entries. On slow logs this
        can delay new entries by up to one poll interval.
        """
        current_index = start_index
        if current_index is None:
            current_index = await self.fetch_tree_size() - 1
            await asyncio.sleep(poll_interval)

        allow_partial = False
        lag: float = 0
        while True:
            loop = asyncio.get_running_loop()
            cycle_start = loop.time()

            got_entries = False
            async for entry in self.fetch_entries(current_index + 1, allow_partial):
                current_index = entry.source.index
                got_entries = True
                yield entry

            allow_partial = not got_entries

            # Sleep for the remaining time in the poll interval
            remaining_time = poll_interval - (loop.time() - cycle_start)

            if remaining_time > 0:
                await asyncio.sleep(remaining_time)
                lag = 0
            else:
                current_lag = -remaining_time
                if current_lag > lag:
                    logger.warning(
                        f"Poll cycle for {self.log_meta.url} exceeded interval by {current_lag:.2f}s"
                    )
                lag = current_lag


class CertificateParser:
    """Parse certificates from CT log entries"""

    @staticmethod
    def parse_x509_certificate(cert_data: bytes) -> x509.Certificate:
        """Parse X.509 certificate from DER bytes"""
        return x509.load_der_x509_certificate(cert_data, default_backend())

    @staticmethod
    def extract_domains(cert: x509.Certificate) -> List[str]:
        """Extract all domains from certificate"""
        domains: List[str] = []

        # Get CN from subject
        try:
            cn_attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attr:
                cn_value = cn_attr[0].value
                # Ensure it's a string
                if isinstance(cn_value, bytes):
                    cn_value = cn_value.decode("utf-8", errors="ignore")
                domains.append(str(cn_value))
        except Exception:
            pass

        # Get SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            domains.extend(san_names)
        except Exception:
            pass

        return list(set(domains))  # Remove duplicates

    @staticmethod
    def calculate_fingerprint(cert_data: bytes, algorithm: str = "sha256") -> str:
        """Calculate certificate fingerprint"""
        if algorithm == "sha256":
            h = hashlib.sha256(cert_data).digest()
        elif algorithm == "sha1":
            h = hashlib.sha1(cert_data).digest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        return ":".join(f"{b:02X}" for b in h)

    @classmethod
    def parse_log_entry(cls, log_entry: LogEntry, source: EntrySource) -> CertificateEntry:
        """Parse a LogEntry into a CertificateEntry"""
        if log_entry.entry_type == EntryType.X509_ENTRY:
            entry_type = "X509LogEntry"
        elif log_entry.entry_type == EntryType.PRECERT_ENTRY:
            entry_type = "PrecertLogEntry"
        else:
            raise ValueError(f"Unknown entry type: {log_entry.entry_type}")

        cert = cls.parse_x509_certificate(log_entry.entry)
        domains = cls.extract_domains(cert)

        return CertificateEntry(
            source=source,
            timestamp=log_entry.timestamp,
            entry_type=entry_type,
            certificate=cert,
            domains=domains,
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            serial_number=format(cert.serial_number, "X"),
            fingerprint_sha256=cls.calculate_fingerprint(log_entry.entry, "sha256"),
            fingerprint_sha1=cls.calculate_fingerprint(log_entry.entry, "sha1"),
        )


class CTMoniteur:
    """
    High-level monitor for all CT logs with state management.

    This is the main entry point for monitoring all CT logs with the ability
    to save and resume from previous state.
    """

    DEFAULT_USER_AGENT = f"CT-Moniteur/{__version__} (github.com/CERT-Polska/ct-moniteur)"

    def __init__(
        self,
        callback: Callable[[CertificateEntry], Optional[Awaitable[None]]],
        initial_state: Optional[Dict[str, int]] = None,
        skip_retired: bool = True,
        poll_interval: float = 30,
        timeout: float = 30.0,
        user_agent: Optional[str] = None,
        max_retries: int = 5,
        retry_delay: float = 10.0,
        refresh_interval: float = 6.0,
    ):
        """
        Initialize CT Moniteur.

        Args:
            callback: Function to call for each certificate entry (can be sync or async)
            initial_state: Optional dict of {log_url: last_index} to resume from
            skip_retired: Skip retired logs
            poll_interval: How often to poll for new entries (seconds)
            timeout: HTTP request timeout
            user_agent: Custom user agent string. Must include an email address, an HTTPS
                URL or a github.com/ link
            max_retries: Maximum retries for failed log connections
            retry_delay: Delay between retries (seconds)
            refresh_interval: How often to refresh the log list (hours, 0 to disable)
        """
        if user_agent:
            _validate_user_agent(user_agent)

        self.callback = callback
        self.skip_retired = skip_retired
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.refresh_interval = refresh_interval

        self._state: Dict[str, int] = initial_state or {}
        self._clients: List[Union[TiledLogClient, ClassicLogClient]] = []
        self._tasks: List[asyncio.Task] = []
        self._running = False
        self._stats = MoniteurStats()
        self._state_lock = asyncio.Lock()
        self._transport = RateLimitedTransport()
        self._refresh_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """
        Start monitoring all CT logs.

        This will fetch the list of all logs and start watching them concurrently.
        Also starts a periodic refresh task to update the log list if enabled.
        """
        if self._running:
            raise RuntimeError("Moniteur is already running")

        self._running = True
        self._stats.start_time = datetime.utcnow()

        self._clients = await self._create_clients()
        self._stats.active_logs = len(self._clients)

        logger.info(f"Starting monitoring of {len(self._clients)} CT logs")

        self._start_watch_tasks()

        if self.refresh_interval > 0:
            self._refresh_task = asyncio.create_task(self._periodic_refresh())

    async def stop(self) -> None:
        """Stop monitoring all logs gracefully."""
        if not self._running:
            return

        logger.info("Stopping CT Moniteur...")
        self._running = False

        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass

        await self._stop_watch_tasks()

        logger.info("CT Moniteur stopped")

    def get_state(self) -> Dict[str, int]:
        """
        Get current monitoring state.

        Returns:
            Dictionary mapping log URLs to last processed index

        Example:
            state = monitor.get_state()
            # Save to file
            with open('ct_state.json', 'w') as f:
                json.dump(state, f)
        """
        return self._state.copy()

    def get_stats(self) -> MoniteurStats:
        """Get monitoring statistics."""
        return self._stats

    async def _create_clients(self) -> List[Union[TiledLogClient, ClassicLogClient]]:
        """Create clients for all CT logs."""
        log_list = await self._fetch_log_list()
        clients: List[Union[TiledLogClient, ClassicLogClient]] = []

        for operator in log_list.get("operators", []):
            operator_name = operator.get("name", "Unknown")

            # Classic logs
            for log in operator.get("logs", []):
                if self.skip_retired and log.get("state", {}).get("retired"):
                    continue

                url = log.get("url", "")
                description = log.get("description", "")

                if url:
                    log_meta = LogMeta(
                        url=url,
                        name=description,
                        operator=operator_name,
                    )
                    classic_client = ClassicLogClient(
                        log_meta=log_meta,
                        timeout=self.timeout,
                        user_agent=self.user_agent,
                        transport=self._transport,
                    )
                    clients.append(classic_client)

            # Tiled logs
            for log in operator.get("tiled_logs", []):
                if self.skip_retired and log.get("state", {}).get("retired"):
                    continue

                url = log.get("monitoring_url", "")
                description = log.get("description", "")

                if url:
                    log_meta = LogMeta(
                        url=url,
                        name=description,
                        operator=operator_name,
                    )
                    tiled_client = TiledLogClient(
                        log_meta=log_meta,
                        timeout=self.timeout,
                        user_agent=self.user_agent,
                        transport=self._transport,
                    )
                    clients.append(tiled_client)

        return clients

    async def _fetch_log_list(self) -> Dict[str, Any]:
        """Fetch the list of all CT logs."""
        headers = {"User-Agent": self.user_agent or self.DEFAULT_USER_AGENT}
        async with httpx2.AsyncClient(headers=headers, transport=self._transport) as client:
            response = await client.get(LOG_LIST_URL, timeout=10.0)
            response.raise_for_status()
            return cast(Dict[str, Any], response.json())

    async def _watch_log(
        self, client: Union[TiledLogClient, ClassicLogClient], initial_delay: float = 0
    ) -> None:
        """Watch a single log with retry logic."""
        # Apply staggered start delay
        if initial_delay > 0:
            await asyncio.sleep(initial_delay)

        retries = 0
        start_index = self._state.get(client.log_meta.url)

        while self._running:
            try:
                async for entry in client.watch(
                    start_index=start_index, poll_interval=self.poll_interval
                ):
                    if not self._running:
                        break

                    # Update state
                    async with self._state_lock:
                        self._state[entry.source.log.url] = entry.source.index
                        self._stats.total_entries_processed += 1
                        self._stats.entries_per_log[entry.source.log.url] = (
                            self._stats.entries_per_log.get(entry.source.log.url, 0) + 1
                        )

                    start_index = entry.source.index

                    # Reset retries on successful entry processing
                    if retries > 0:
                        logger.info(
                            f"Log {client.log_meta.url} recovered after {retries} failed attempt(s)"
                        )
                        retries = 0

                    # Call user callback
                    try:
                        result = self.callback(entry)
                        if inspect.isawaitable(result):
                            await result
                    except Exception as e:
                        logger.error(
                            f"Error in callback for {entry.source.log.url}: {e}", exc_info=True
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                retries += 1

                # Update error stats
                async with self._state_lock:
                    self._stats.errors_per_log[client.log_meta.url] = (
                        self._stats.errors_per_log.get(client.log_meta.url, 0) + 1
                    )

                logger.warning(
                    f"Error watching {client.log_meta.url} (retry {retries}/{self.max_retries}): "
                    f"{str(e) or type(e).__name__}"
                )

                if retries >= self.max_retries:
                    logger.error(f"Max retries reached for {client.log_meta.url}, giving up")
                    break

                await asyncio.sleep(self.retry_delay)

    async def _periodic_refresh(self) -> None:
        """
        Periodically refresh the log list and restart clients.

        This task runs in the background and refreshes the log list at the
        specified interval. If the log list fetch fails, it logs the error
        and continues with the existing clients.
        """
        while self._running:
            try:
                await asyncio.sleep(self.refresh_interval * 3600)

                if not self._running:
                    break

                logger.info("Refreshing CT log list...")

                try:
                    new_clients = await self._create_clients()
                    logger.info(f"Fetched updated log list: {len(new_clients)} logs available")

                    await self._restart_clients(new_clients)

                    logger.info(f"Successfully restarted with {len(new_clients)} CT logs")

                except Exception as e:
                    logger.error(
                        f"Failed to fetch updated log list, continuing with existing clients: {e}"
                    )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic refresh task: {e}", exc_info=True)

    async def _restart_clients(
        self, new_clients: List[Union[TiledLogClient, ClassicLogClient]]
    ) -> None:
        """
        Stop all current clients and start new ones.

        Args:
            new_clients: List of new clients to start monitoring
        """
        await self._stop_watch_tasks()

        self._clients = new_clients
        self._stats.active_logs = len(new_clients)

        self._start_watch_tasks()

    async def _stop_watch_tasks(self) -> None:
        """
        Stop all watch tasks and close clients.

        Cancels all running watch tasks, waits for them to finish,
        closes all clients, and clears the task list.
        """
        for task in self._tasks:
            task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        for client in self._clients:
            await client.close()

        self._tasks.clear()

    def _start_watch_tasks(self) -> None:
        """
        Start watch tasks for all clients with staggered delays.

        Creates watch tasks with evenly distributed initial delays to avoid
        request bursts when polling logs.
        """
        for i, client in enumerate(self._clients):
            delay = i * self.poll_interval / len(self._clients)
            task = asyncio.create_task(self._watch_log(client, initial_delay=delay))
            self._tasks.append(task)

    @staticmethod
    async def fetch_all_logs(user_agent: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fetch the list of all CT logs from Google's log list.

        Args:
            user_agent: Custom user agent string to use for the request

        Returns:
            Dictionary containing operators and their logs
        """
        headers = {"User-Agent": user_agent or CTMoniteur.DEFAULT_USER_AGENT}
        async with httpx2.AsyncClient(headers=headers, transport=RateLimitedTransport()) as client:
            response = await client.get(LOG_LIST_URL, timeout=10.0)
            response.raise_for_status()
            return cast(Dict[str, List[Dict[str, Any]]], response.json())
