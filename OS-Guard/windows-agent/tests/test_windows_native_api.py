import ctypes
import unittest

from agent.checks.common import (
    NativeWindowsReadOnlyApi,
    WindowsApiUnavailable,
    _UserInfo3,
    _UserModalsInfo3,
)
from agent.windows_checks import collect_check


class _PagedNetApi:
    def __init__(self, pages):
        self.pages = pages
        self.calls = 0
        self.buffers = []
        self.freed = 0

    def NetUserEnum(self, server, level, account_filter, buffer, preferred, entries, total, resume):
        self.asserted_level = level
        page_index = resume._obj.value
        status, records = self.pages[page_index]
        rows = (_UserInfo3 * len(records))()
        for row, (name, user_id, flags) in zip(rows, records):
            row.name = name
            row.user_id = user_id
            row.flags = flags
        self.buffers.append(rows)
        buffer._obj.value = ctypes.addressof(rows) if records else None
        entries._obj.value = len(records)
        total._obj.value = sum(len(page_records) for _, page_records in self.pages)
        resume._obj.value = page_index + 1
        self.calls += 1
        return status

    def NetApiBufferFree(self, buffer):
        self.freed += 1
        return 0


class NativeWindowsApiTests(unittest.TestCase):
    def test_net_user_enum_pagination_feeds_w01_w02_w03(self):
        netapi = _PagedNetApi([
            (234, [("RenamedAdmin", 500, 0)]),
            (0, [("Guest", 501, 0x2), ("Operator", 1001, 0)]),
        ])
        api = NativeWindowsReadOnlyApi.__new__(NativeWindowsReadOnlyApi)
        api._netapi = netapi

        accounts = api.accounts()
        self.assertEqual(netapi.asserted_level, 3)
        self.assertEqual(netapi.calls, 2)
        self.assertEqual(netapi.freed, 2)
        self.assertEqual(collect_check("W-01", api).status, "PASS")
        self.assertEqual(collect_check("W-02", api).status, "PASS")
        w03 = collect_check("W-03", api)
        self.assertEqual(w03.status, "UNABLE")
        self.assertEqual(w03.current_value["account_count"], 3)
        self.assertNotIn("Operator", str(w03.current_value))

    def test_net_user_enum_error_is_not_hidden(self):
        netapi = _PagedNetApi([(5, [])])
        api = NativeWindowsReadOnlyApi.__new__(NativeWindowsReadOnlyApi)
        api._netapi = netapi
        with self.assertRaisesRegex(WindowsApiUnavailable, "NetUserEnum failed: 5"):
            api.accounts()

    def test_user_modals_info_3_maps_threshold_after_time_fields(self):
        class NetApi:
            def __init__(self):
                self.policy = _UserModalsInfo3(3600, 1800, 5)
            def NetUserModalsGet(self, server, level, buffer):
                self.level = level
                buffer._obj.value = ctypes.addressof(self.policy)
                return 0
            def NetApiBufferFree(self, buffer):
                return 0

        api = NativeWindowsReadOnlyApi.__new__(NativeWindowsReadOnlyApi)
        api._netapi = NetApi()
        policy = api.lockout_policy()
        self.assertEqual(api._netapi.level, 3)
        self.assertEqual(policy, {"threshold": 5, "reset_seconds": 1800, "duration_seconds": 3600})
        self.assertEqual(collect_check("W-04", api).status, "PASS")


if __name__ == "__main__":
    unittest.main()
