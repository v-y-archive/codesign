import os
import mmap
import plistlib
import zipfile
import tempfile
from glob import glob

kSecCodeMagicRequirement		= b"\xFA\xDE\x0C\x00"	# Single requirement
kSecCodeMagicRequirementSet		= b"\xFA\xDE\x0C\x01"	# Requirement set
kSecCodeMagicCodeDirectory		= b"\xFA\xDE\x0C\x02"	# CodeDirectory
kSecCodeMagicEmbeddedSignature	= b"\xFA\xDE\x0C\xC0"	# Single-architecture embedded signature
kSecCodeMagicDetachedSignature	= b"\xFA\xDE\x0C\xC1"	# Detached multi-architecture signature
kSecCodeMagicEntitlement		= b"\xFA\xDE\x71\x71"	# Entitlement blob

def get_entitlements(executable):
	"""Get application entitlements."""
	with open(executable, "rb") as f:
		mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
		entitlement_blob_offset = mm.rfind(kSecCodeMagicEntitlement)
		mm.seek(entitlement_blob_offset + 4, os.SEEK_SET)
		entitlement_blob_size = int.from_bytes(mm.read(4), byteorder="big") - 8
		entitlement_blob = mm.read(entitlement_blob_size)
		mm.close()
	entitlements = plistlib.loads(entitlement_blob)
	return entitlements

def get_ipa_entitlements(ipa_path):
	"""Get application entitlements from .ipa file"""
	with tempfile.TemporaryDirectory as tmp_dir:
		with zipfile.ZipFile(ipa_path, "r") as zip_ref:
			zip_ref.extractall(tmp_dir)
		app_dir = glob(f"{tmp_dir}/Payload/*.app")[0]
		app_executable = os.path.basename(app_dir).split(".")[0]
		return get_entitlements(app_executable)
