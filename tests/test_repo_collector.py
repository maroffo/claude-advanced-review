# ABOUTME: Unit tests for runner/repo_collector.py file collection and chunking
# ABOUTME: Tests skeleton generation, directory-based chunking, .gitignore filtering

from __future__ import annotations

import textwrap

from runner import repo_collector as RC


# ---------- collect_files tests ----------

class TestCollectFiles:
    def test_collects_python_files(self, tmp_path):
        (tmp_path / "app.py").write_text("print('hi')")
        (tmp_path / "lib.py").write_text("x = 1")
        files = RC.collect_files(tmp_path)
        assert len(files) == 2

    def test_skips_hidden_dirs(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("x")
        (tmp_path / "app.py").write_text("x")
        files = RC.collect_files(tmp_path)
        assert all(".git" not in str(f) for f in files)

    def test_skips_vendor_dirs(self, tmp_path):
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "lib.go").write_text("package lib")
        (tmp_path / "main.go").write_text("package main")
        files = RC.collect_files(tmp_path)
        names = [f.name for f in files]
        assert "lib.go" not in names
        assert "main.go" in names

    def test_skips_node_modules(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "pkg.js").write_text("x")
        (tmp_path / "index.js").write_text("x")
        files = RC.collect_files(tmp_path)
        assert len(files) == 1

    def test_skips_binary_files(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        files = RC.collect_files(tmp_path)
        assert len(files) == 1

    def test_respects_subpath(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x")
        (tmp_path / "other.py").write_text("x")
        files = RC.collect_files(tmp_path / "src")
        assert len(files) == 1

    def test_skips_lockfiles(self, tmp_path):
        (tmp_path / "app.py").write_text("x")
        (tmp_path / "uv.lock").write_text("x")
        (tmp_path / "package-lock.json").write_text("{}")
        files = RC.collect_files(tmp_path)
        names = [f.name for f in files]
        assert "uv.lock" not in names
        assert "package-lock.json" not in names


# ---------- generate_skeleton tests ----------

class TestGenerateSkeleton:
    def test_extracts_python_functions(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text(textwrap.dedent("""\
            def hello():
                pass

            class Foo:
                def bar(self, x):
                    return x
        """))
        skeleton = RC.generate_skeleton([src])
        assert "def hello()" in skeleton
        assert "class Foo" in skeleton
        assert "def bar(self, x)" in skeleton

    def test_extracts_go_functions(self, tmp_path):
        src = tmp_path / "main.go"
        src.write_text(textwrap.dedent("""\
            package main

            func Hello(name string) string {
                return "hi " + name
            }

            type Server struct {
                Port int
            }
        """))
        skeleton = RC.generate_skeleton([src])
        assert "func Hello(name string)" in skeleton
        assert "type Server struct" in skeleton

    def test_extracts_js_functions(self, tmp_path):
        src = tmp_path / "app.js"
        src.write_text(textwrap.dedent("""\
            function greet(name) {
                return `hi ${name}`;
            }

            class UserService {
                async getUser(id) {}
            }
        """))
        skeleton = RC.generate_skeleton([src])
        assert "function greet(name)" in skeleton
        assert "class UserService" in skeleton

    def test_includes_file_paths(self, tmp_path):
        src = tmp_path / "utils.py"
        src.write_text("def helper(): pass")
        skeleton = RC.generate_skeleton([src])
        assert "utils.py" in skeleton

    def test_empty_files_handled(self, tmp_path):
        src = tmp_path / "empty.py"
        src.write_text("")
        skeleton = RC.generate_skeleton([src])
        assert isinstance(skeleton, str)


# ---------- chunk_by_directory tests ----------

class TestChunkByDirectory:
    def test_groups_by_parent_dir(self, tmp_path):
        (tmp_path / "models").mkdir()
        f1 = tmp_path / "models" / "user.py"
        f2 = tmp_path / "models" / "account.py"
        f3 = tmp_path / "main.py"
        for f in (f1, f2, f3):
            f.write_text("x = 1\n" * 10)
        chunks = RC.chunk_by_directory([f1, f2, f3], max_lines=5000)
        # models/ files should be in same chunk, main.py separate
        assert len(chunks) == 2

    def test_splits_large_directories(self, tmp_path):
        d = tmp_path / "big"
        d.mkdir()
        files = []
        for i in range(5):
            f = d / f"file_{i}.py"
            f.write_text("x = 1\n" * 1000)  # 1000 lines each
            files.append(f)
        chunks = RC.chunk_by_directory(files, max_lines=2500)
        # 5000 total lines, max 2500 per chunk = at least 2 chunks
        assert len(chunks) >= 2

    def test_single_file_is_one_chunk(self, tmp_path):
        f = tmp_path / "solo.py"
        f.write_text("x = 1")
        chunks = RC.chunk_by_directory([f], max_lines=5000)
        assert len(chunks) == 1
        assert f in chunks[0]

    def test_preserves_all_files(self, tmp_path):
        files = []
        for i in range(10):
            f = tmp_path / f"f{i}.py"
            f.write_text("x")
            files.append(f)
        chunks = RC.chunk_by_directory(files, max_lines=5000)
        all_chunked = [f for chunk in chunks for f in chunk]
        assert set(all_chunked) == set(files)
