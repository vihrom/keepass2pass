#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from xml.etree import ElementTree as ET

from keepass2pass import (
    sanitize_component,
    normalize_root,
    entry_fields,
    format_entry,
    Collector,
    SEPARATOR,
)


class TestKeePass2Pass(unittest.TestCase):

    def test_sanitize_component(self):
        """Test sanitization of path components to remove dangerous characters."""
        self.assertEqual(sanitize_component("hello/world"), "hello_world")
        self.assertEqual(sanitize_component("test\x00name"), "test_name")
        self.assertEqual(sanitize_component("."), "_")
        self.assertEqual(sanitize_component(".."), "_")
        self.assertEqual(sanitize_component("   "), "untitled")

    def test_normalize_root(self):
        """Test root path normalization."""
        self.assertEqual(normalize_root("a//b/"), "a/b")
        self.assertEqual(normalize_root("  "), "")  # Whitespace collapses to empty string (flat)
        self.assertEqual(normalize_root(""), "")

    def test_entry_fields_parsing(self):
        """Test extraction of fields from an entry XML element."""
        xml_data = """
        <Entry>
            <String><Key>Title</Key><Value>GitHub</Value></String>
            <String><Key>Password</Key><Value>supersecret</Value></String>
            <String><Key>UserName</Key><Value>developer</Value></String>
        </Entry>
        """
        entry = ET.fromstring(xml_data)
        fields = entry_fields(entry)
        
        self.assertEqual(fields.get("Title"), "GitHub")
        self.assertEqual(fields.get("Password"), "supersecret")
        self.assertEqual(fields.get("UserName"), "developer")

    def test_format_entry_structure(self):
        """Test pass format structure (password on first line, OTP without key prefix)."""
        xml_data = """
        <Entry>
            <String><Key>Title</Key><Value>Email</Value></String>
            <String><Key>Password</Key><Value>mypassword</Value></String>
            <String><Key>UserName</Key><Value>user@mail.com</Value></String>
            <String><Key>otp</Key><Value>otpauth://totp/Test?secret=XYZ</Value></String>
        </Entry>
        """
        entry = ET.fromstring(xml_data)
        fields = entry_fields(entry)
        result = format_entry(entry, fields, "Email")
        
        lines = result.splitlines()
        self.assertEqual(lines[0], "mypassword")  # Password must be on the first line
        self.assertIn("UserName: user@mail.com", lines)
        self.assertIn("otpauth://totp/Test?secret=XYZ", lines)  # OTP without key prefix

    def test_collector_duplicate_split(self):
        """Test 'split' duplicate strategy (appending suffix _2)."""
        collector = Collector(duplicates="split", bin_uuid=None)
        collector.entries["MyService"] = "password123\n"

        xml_data = """
        <Entry>
            <String><Key>Title</Key><Value>MyService</Value></String>
            <String><Key>Password</Key><Value>anotherpassword</Value></String>
        </Entry>
        """
        entry = ET.fromstring(xml_data)
        collector.add_entry(entry, "")

        self.assertIn("MyService", collector.entries)
        self.assertIn("MyService_2", collector.entries)
        self.assertEqual(collector.entries["MyService_2"], "anotherpassword\n")

    def test_collector_duplicate_merge(self):
        """Test 'merge' duplicate strategy."""
        collector = Collector(duplicates="merge", bin_uuid=None)
        collector.entries["MyService"] = "first_pass\n"

        xml_data = """
        <Entry>
            <String><Key>Title</Key><Value>MyService</Value></String>
            <String><Key>Password</Key><Value>second_pass</Value></String>
        </Entry>
        """
        entry = ET.fromstring(xml_data)
        collector.add_entry(entry, "")

        self.assertIn("MyService", collector.entries)
        self.assertIn(SEPARATOR, collector.entries["MyService"])
        self.assertIn("second_pass", collector.entries["MyService"])


if __name__ == "__main__":
    unittest.main()
