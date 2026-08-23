from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rapp_herdr.model import RappHerdrError, load_neighborhood, resolve_topology

from tests.helpers import create_neighborhood, create_twin, write_json


class ModelTests(unittest.TestCase):
    def test_four_twin_neighborhood_resolves_in_membership_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, rappids = create_neighborhood(root / "neighborhood")
            estate = root / "estate"
            for index, rappid in enumerate(reversed(rappids), 1):
                create_twin(estate, f"twin-{index}", rappid)

            neighborhood = load_neighborhood(manifest)
            topology = resolve_topology(neighborhood, [estate], require_all_local=True)

            self.assertEqual([twin.rappid for twin in topology.twins], rappids)
            self.assertEqual(len(topology.twins), 4)
            self.assertEqual(topology.unresolved_rappids, ())

    def test_remote_members_are_reported_without_becoming_local_processes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, rappids = create_neighborhood(root / "neighborhood")
            estate = root / "estate"
            create_twin(estate, "only-local", rappids[0])

            topology = resolve_topology(load_neighborhood(manifest), [estate])

            self.assertEqual([twin.rappid for twin in topology.twins], [rappids[0]])
            self.assertEqual(topology.unresolved_rappids, tuple(rappids[1:]))

    def test_require_all_local_rejects_remote_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, rappids = create_neighborhood(root / "neighborhood")
            estate = root / "estate"
            create_twin(estate, "only-local", rappids[0])

            with self.assertRaisesRegex(RappHerdrError, "not present"):
                resolve_topology(
                    load_neighborhood(manifest),
                    [estate],
                    require_all_local=True,
                )

    def test_duplicate_local_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, rappids = create_neighborhood(root / "neighborhood", count=1)
            estate = root / "estate"
            create_twin(estate, "one", rappids[0])
            create_twin(estate, "two", rappids[0])

            with self.assertRaisesRegex(RappHerdrError, "duplicate local Twin identity"):
                resolve_topology(load_neighborhood(manifest), [estate])

    def test_unrelated_incomplete_twin_does_not_block_selected_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, rappids = create_neighborhood(root / "neighborhood", count=1)
            estate = root / "estate"
            create_twin(estate, "selected", rappids[0])
            unrelated = estate / "unrelated"
            write_json(
                unrelated / "rappid.json",
                {
                    "rappid": "rappid:@test/unrelated:" + "d" * 64,
                    "kind": "twin",
                    "name": "unrelated",
                },
            )

            topology = resolve_topology(load_neighborhood(manifest), [estate])

            self.assertEqual([twin.rappid for twin in topology.twins], rappids)

    def test_unrelated_identity_without_kind_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, rappids = create_neighborhood(root / "neighborhood", count=1)
            estate = root / "estate"
            create_twin(estate, "selected", rappids[0])
            write_json(
                estate / "unrelated" / "rappid.json",
                {
                    "rappid": "rappid:@test/unrelated:" + "e" * 64,
                    "name": "unrelated",
                },
            )

            topology = resolve_topology(load_neighborhood(manifest), [estate])

            self.assertEqual([twin.rappid for twin in topology.twins], rappids)

    def test_members_path_cannot_escape_neighborhood(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, _ = create_neighborhood(root / "neighborhood")
            write_json(
                manifest,
                {
                    "schema": "rapp-neighborhood/1.0",
                    "name": "bad",
                    "neighborhood_rappid": "rappid:@test/bad:" + "b" * 64,
                    "members_path": "../members.json",
                },
            )

            with self.assertRaisesRegex(RappHerdrError, "escapes"):
                load_neighborhood(manifest)

    def test_vneighborhood_uses_channel_as_application_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "neighborhood.json"
            write_json(
                manifest,
                {
                    "schema": "rapp-vneighborhood/1.0",
                    "name": "Design Studio",
                    "channel": "design-studio",
                },
            )
            write_json(
                root / "members.json",
                {
                    "schema": "rapp-neighborhood-members/1.0",
                    "members": [{"rappid": "rappid:@test/designer:" + "c" * 64}],
                },
            )

            neighborhood = load_neighborhood(manifest)

            self.assertEqual(neighborhood.semantic_id, "channel:design-studio")


if __name__ == "__main__":
    unittest.main()
