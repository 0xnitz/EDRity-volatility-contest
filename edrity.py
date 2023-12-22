from time import sleep
from requests import get  # Using requests to grab the final analysis from VT
from logging import getLogger
from typing import Dict, Tuple
from virustotal_python import Virustotal
from json import loads, JSONDecodeError, dump

from volatility3.framework.interfaces import plugins
from volatility3.framework import renderers, exceptions
from volatility3.framework.renderers import format_hints
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import malfind, pslist, vadinfo

vollog = getLogger(__file__)

# TODO: in the future, add custom extractions/evaulations in the edrity plugin itself, like relocation resolving, shellcode extraction/unpacking, etc.


class EDRity(plugins.PluginInterface):
    """Extract usermode floating MZ's and upload to VirusTotal.\n
    This plugin is best used with the volatility live winpmem layer"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    PE_MAGIC = b"MZ"

    MAX_RETRIES = 5
    VT_WAIT_BETWEEN_RETRIES = 1

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="api_key",
                description="VirusTotal API key",
                default=None,
                optional=False,
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="verbose",
                description="Print out engine results",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="verbose_file",
                description="Write engine JSON output to a file",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="malicious",
                description="Print out only malicious results",
                default=False,
                optional=True,
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="vadinfo", plugin=vadinfo.VadInfo, version=(2, 0, 0)
            ),
        ]

    @staticmethod
    def dump_vad_from_memory(context, process, vad, open_method) -> None:
        file_output = "Error outputting to file"
        try:
            file_handle = vadinfo.VadInfo.vad_dump(context, process, vad, open_method)
            file_handle.close()
            file_output = file_handle.preferred_filename
        except (
            exceptions.InvalidAddressException,
            OverflowError,
        ) as exception:
            vollog.debug(
                "Unable to dump PE with pid {0}.{1:#x}: {2}".format(
                    process.UniqueProcessId, vad.get_start(), exception
                )
            )

        return file_output

    @staticmethod
    def write_json_to_file(json_data, file_name) -> None:
        with open(file_name, "w") as json_file:
            dump(json_data, json_file)
            vollog.info(f"[+] Wrote JSON to file {file_name}")

    def send_file_to_vt(self, virustotal, files: Dict) -> str:
        vt_response = virustotal.request("files", files=files, method="POST")
        vt_id = vt_response.data["id"]
        headers = {"x-apikey": self.config["api_key"]}
        retries = 0

        while retries < self.MAX_RETRIES:
            retries += 1
            sleep(EDRity.VT_WAIT_BETWEEN_RETRIES)

            vt_analysis = get(
                f"https://www.virustotal.com/api/v3/analyses/{vt_id}",
                headers=headers,
            )

            try:
                response_json = vt_analysis.json()
                if response_json["data"]["attributes"]["status"] != "queued":
                    return vt_analysis.text
            except (JSONDecodeError, KeyError):
                continue

        vollog.error(f'Max retries reached while polling VT for {vt_id}!')

        return vt_analysis.text

    def parse_vt_results(self, vt_analysis_text) -> Tuple[Dict, int, float]:
        try:
            analysis_json = loads(vt_analysis_text)
            engine_stats = analysis_json["data"]["attributes"]["stats"]
            malicious = engine_stats["malicious"]
        except (JSONDecodeError, KeyError):
            vollog.error(f"Invalid response from VT: {vt_analysis_text}")

            return None, None, None

        total = 0
        for engine in engine_stats:
            total += engine_stats[engine]
        malicious_score = (malicious / total) if total else 0

        return analysis_json, malicious, malicious_score

    def _generator(self, process_list, kernel):
        virustotal = Virustotal(API_KEY=self.config["api_key"], TIMEOUT=10)

        for process in process_list:
            process_name = process.ImageFileName.cast(
                "string",
                max_length=process.ImageFileName.vol.count,
                errors="replace",
            )
            pid = process.UniqueProcessId

            vollog.info(f"[+] Scanning process {process_name}:{pid}")

            for vad, data in malfind.Malfind.list_injections(
                self.context, kernel.layer_name, kernel.symbol_table_name, process
            ):
                if data.startswith(EDRity.PE_MAGIC):
                    filename = ''

                    vollog.info(
                        f"[+] Found floating MZ in {process_name}:{pid} at {hex(vad.get_start())}!"
                    )
                    file_output = self.dump_vad_from_memory(
                        self.context, process, vad, self.open
                    )
                    files = {"file": (file_output, open(file_output, "rb"))}

                    vt_analysis_text = self.send_file_to_vt(virustotal, files)
                    analysis_str = vt_analysis_text if self.config["verbose"] else ""
                    analysis_json, malicious, malicious_score = self.parse_vt_results(
                        vt_analysis_text
                    )
                    if not analysis_json:
                        continue

                    if self.config["malicious"] and malicious == 0:
                        continue

                    if self.config["verbose_file"]:
                        filename = (
                            f"edrity_{process_name}_{pid}_{hex(vad.get_start())}.json"
                        )
                        self.write_json_to_file(analysis_json, filename)

                    yield (
                        0,
                        (
                            process_name,
                            pid,
                            format_hints.Hex(vad.get_start()),
                            format_hints.Hex(vad.get_end()),
                            malicious,
                            float(malicious_score),
                            analysis_str,
                            filename,
                        ),
                    )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("Process", str),
                ("PID", int),
                ("VAD Start", format_hints.Hex),
                ("VAD End", format_hints.Hex),
                ("Malicious", int),
                ("Malicious Score", float),
                ("VirusTotal Response", str),
                ("Filename", str)
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=filter_func,
                ),
                kernel,
            ),
        )
