"""
worker.py

    Implements the actual reverse engineering used by both the
"""
import os
import re
import logging
import typings as t

import lief


class BoaWorker:
    def __init__(self, filepath, cli = False):
        self.filepath = filepath

        # if set, will not attempt to pingback any endpoints
        self.cli = cli

        # wrap LIEF over to parse executable
        self.binary = lief.parse(self.filepath)
        if isinstance(self.binary, lief.PE.Binary):
            self.format = "PE"
        elif isinstance(self.binary, lief.ELF.Binary):
            self.format = "ELF"
        elif isinstance(self,binary, lief.MachO.Binary):
            raise WorkerException("Mach-O's are not supported yet.")

        # regex search for python dependency
        self.pyver: t.Optional[float] = self._parse_pyver()

    def _parse_pyver(self) -> t.Optional[float]:
        """ Generically searches for python dependency (DLL/SO) in executbale format """

        # iterate over symbols
        section = self.binary.get_section(".data")
        data: bytes = bytearray(section.content)

        # search for python dependency
        expr : str = r"python(\d+)"
        matches = re.search(expr, str(data))
        if matches is None:
            return None

        # strip out name and extension
        res: t.List[str] = list(matches.group(0).split("python")[1].strip(".dll"))
        res.insert(1, ".")
        return float("".join(res))


    def run_detect(self) -> t.Dict[str, str]:
        """ Given a blob of data, run initial detection to gather metadata """

        # generate table of hashes useful for analyst
        hashes: t.Dict[str, str] = {}
        hashes["MD5"] = hashlib.md5(data).hexdigest()
        hashes["SHA256"] = hashlib.sha256(data).hexdigest()
        hashes["Similiarity Hash (ssdeep)"] = ssdeep.hash(data)

        # VT checks are optional, and only occur if $VT_API is set
        vt_api: t.Optional[str] = os.environ.get("VT_API")
        if vt_api:
            params = {"apiKey": vt_api}
            files = {"file": binary}
            resp = requests.post(
                "https://www.virustotal.com/vtapi/v2/file/scan", files=files, params=params
            )
            print(resp.json())

        return hashes

    def run_unpack(self) -> int:
        pass

    def run_decompile(self) -> int:
        pass
