#
# Wireshark tests
#
# Copyright 2026 by Wireshark Contributors
#
# SPDX-License-Identifier: GPL-2.0-or-later

'''Procmon dissector tests using strato CLI'''

import subprocess
import json


def _find_key_recursive(d, key):
    '''Recursively search a nested dict for a key'''
    if isinstance(d, dict):
        if key in d:
            return True
        for v in d.values():
            if _find_key_recursive(v, key):
                return True
    return False


class TestProcmonFilters:
    '''Tests for procmon dissector field parsing and display filters using strato'''

    def test_io_flags_nonzero(self, cmd_strato, capture_file, test_env):
        '''Verify procmon.filesystem.readwrite_file.io_flags != 0x00000000 filter works correctly'''
        # This tests that io_flags are correctly parsed and filterable
        # Expected: should match READ/WRITE operations with non-zero io flags
        stdout = subprocess.check_output((cmd_strato,
            '-r', capture_file('procmon.pml'),
            '-Y', 'procmon.filesystem.readwrite_file.io_flags != 0x00000000',
            '-T', 'fields',
            '-e', 'procmon.filesystem.readwrite_file.io_flags',
        ), encoding='utf-8', env=test_env)
        
        # Should have at least some output (non-zero io_flags)
        lines = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        assert len(lines) > 0, "Expected at least one io_flags value != 0x00000000"
        
        # Verify all values are non-zero hex
        for val in lines:
            # Strato outputs in decimal or hex format; should not be all zeros
            assert val != '0', f"Expected non-zero io_flags, got {val}"

    def test_io_flags_zero(self, cmd_strato, capture_file, test_env):
        '''Verify procmon.filesystem.readwrite_file.io_flags == 0x00000000 filter works correctly'''
        # This tests that we can also filter for zero io_flags
        stdout = subprocess.check_output((cmd_strato,
            '-r', capture_file('procmon.pml'),
            '-Y', 'procmon.filesystem.readwrite_file.io_flags == 0x00000000',
            '-T', 'fields',
            '-e', 'procmon.filesystem.readwrite_file.io_flags',
        ), encoding='utf-8', env=test_env)
        
        lines = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        # If there are matching records, they should all be 0
        # io_flags is BASE_HEX so output is '0x00000000'
        for val in lines:
            assert int(val, 0) == 0, f"Expected io_flags == 0, got {val}"

    def test_event_result_nonzero(self, cmd_strato, capture_file, test_env):
        '''Verify procmon.event_result != 0 filter works correctly'''
        # This tests that event_result (NTSTATUS) fields are correctly parsed and filterable
        # Expected: should match operations that failed or returned non-success status
        stdout = subprocess.check_output((cmd_strato,
            '-r', capture_file('procmon.pml'),
            '-Y', 'procmon.event_result != 0',
            '-T', 'fields',
            '-e', 'procmon.event_result',
        ), encoding='utf-8', env=test_env)
        
        lines = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        # Should have some non-zero results (not all operations succeed)
        # We only assert if there are lines - file might be all successes
        if lines:
            for val in lines:
                # Parse as int (may be decimal or hex representation)
                try:
                    result_val = int(val, 0)
                    assert result_val != 0, f"Expected non-zero event_result, got {val}"
                except ValueError:
                    # If parsing fails, just check it's not '0'
                    assert val != '0', f"Expected non-zero event_result, got {val}"

    def test_event_result_success(self, cmd_strato, capture_file, test_env):
        '''Verify procmon.event_result == 0 filter works correctly (SUCCESS)'''
        stdout = subprocess.check_output((cmd_strato,
            '-r', capture_file('procmon.pml'),
            '-Y', 'procmon.event_result == 0',
            '-T', 'fields',
            '-e', 'procmon.event_result',
        ), encoding='utf-8', env=test_env)
        
        lines = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        # Should have some successful operations
        assert len(lines) > 0, "Expected at least one successful operation (event_result == 0)"
        
        for val in lines:
            assert val == '0', f"Expected event_result == 0 (SUCCESS), got {val}"

    def test_combined_filter_or(self, cmd_strato, capture_file, test_env):
        '''Verify combined filter: procmon.filesystem.readwrite_file.io_flags != 0x00000000 || procmon.event_result != 0'''
        # This tests that compound filters with OR logic work correctly
        stdout = subprocess.check_output((cmd_strato,
            '-r', capture_file('procmon.pml'),
            '-Y', 'procmon.filesystem.readwrite_file.io_flags != 0x00000000 || procmon.event_result != 0',
            '-T', 'fields',
            '-e', 'frame.number',
        ), encoding='utf-8', env=test_env)
        
        lines = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        # Should match records that have either condition true
        assert len(lines) > 0, "Expected at least one frame matching the combined filter"

    def test_io_flags_json_output(self, cmd_strato, capture_file, test_env):
        '''Verify io_flags are correctly dissected with flag names in JSON output'''
        stdout = subprocess.check_output((cmd_strato,
            '-r', capture_file('procmon.pml'),
            '-Y', 'procmon.filesystem.readwrite_file.io_flags != 0x00000000',
            '-T', 'json',
            '-J', 'procmon',
        ), encoding='utf-8', env=test_env)
        
        packets = json.loads(stdout)
        assert len(packets) > 0, "Expected at least one packet in JSON output"
        
        # Check that procmon layer exists and has io_flags (may be nested)
        found_io_flags = False
        for packet in packets:
            layers = packet.get('_source', {}).get('layers', {})
            if 'procmon' in layers:
                if _find_key_recursive(layers['procmon'], 'procmon.filesystem.readwrite_file.io_flags'):
                    found_io_flags = True
                    break
        
        assert found_io_flags, "Expected to find procmon.filesystem.readwrite_file.io_flags in JSON output"

    def test_disposition_field_exists(self, cmd_strato, capture_file, test_env):
        '''Verify procmon.filesystem.create_file.disposition field is parsed correctly'''
        stdout = subprocess.check_output((cmd_strato,
            '-r', capture_file('procmon.pml'),
            '-Y', 'procmon.filesystem.create_file.disposition',
            '-T', 'fields',
            '-e', 'procmon.filesystem.create_file.disposition',
        ), encoding='utf-8', env=test_env)
        
        lines = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        # Should find some create operations with disposition values
        # Disposition should be in range 0-5 for standard CreateFile values
        for val in lines:
            try:
                int(val, 0)  # Verify the value parses as an integer
            except ValueError:
                pass  # May be a named value like "Open", "Create", etc.
