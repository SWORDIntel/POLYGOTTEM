#!/usr/bin/env python3
"""
POLYGOTTEM C Methods Compiler and Manager
===========================================

Manages compilation and execution of C-based exploitation methods.
Provides Python interface to native C implementations for defensive research.

EDUCATIONAL/RESEARCH USE ONLY - AUTHORIZED TESTING REQUIRED
"""

import os
import sys
import subprocess
import platform
import ctypes
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, List, Tuple

class PolygottemCCompiler:
    """Manages compilation of C methods library"""

    def __init__(self, verbose: bool = False):
        """Initialize C compiler manager"""
        self.verbose = verbose
        self.root_dir = Path(__file__).parent.parent
        self.c_methods_dir = self.root_dir / "c_methods"
        self.build_dir = self.c_methods_dir / "build"
        self.lib_dir = self.build_dir / "lib"
        self.platform_name = platform.system().lower()
        self.arch = platform.machine()
        self.compiled_library = None
        self.c_library = None

    def log(self, message: str, level: str = "INFO"):
        """Log message if verbose"""
        if self.verbose:
            print(f"[{level}] {message}")

    def check_compiler(self) -> bool:
        """Check if C compiler is available"""
        compilers = {
            "windows": "cl.exe",
            "darwin": "clang",
            "linux": "gcc",
        }

        compiler = compilers.get(self.platform_name, "gcc")

        try:
            result = subprocess.run([compiler, "--version"], capture_output=True)
            self.log(f"Found compiler: {compiler}")
            return result.returncode == 0
        except FileNotFoundError:
            self.log(f"Compiler not found: {compiler}", "ERROR")
            return False

    def create_build_directory(self) -> bool:
        """Create build directory if it doesn't exist"""
        try:
            self.build_dir.mkdir(parents=True, exist_ok=True)
            self.log(f"Build directory ready: {self.build_dir}")
            return True
        except Exception as e:
            self.log(f"Failed to create build directory: {e}", "ERROR")
            return False

    def compile_with_cmake(self) -> bool:
        """Compile using CMake"""
        try:
            # Configure CMake
            self.log("Configuring CMake...")
            configure_cmd = [
                "cmake",
                "-S", str(self.c_methods_dir),
                "-B", str(self.build_dir),
                "-DCMAKE_BUILD_TYPE=Release",
            ]

            result = subprocess.run(configure_cmd, cwd=self.c_methods_dir, capture_output=True)
            if result.returncode != 0:
                self.log(f"CMake configuration failed: {result.stderr.decode()}", "ERROR")
                return False

            # Build
            self.log("Building C methods library...")
            build_cmd = ["cmake", "--build", str(self.build_dir), "--config", "Release"]

            result = subprocess.run(build_cmd, cwd=self.build_dir, capture_output=True)
            if result.returncode != 0:
                self.log(f"CMake build failed: {result.stderr.decode()}", "ERROR")
                return False

            self.log("Successfully compiled C methods library")
            return True

        except Exception as e:
            self.log(f"Compilation error: {e}", "ERROR")
            return False

    def compile_manual(self) -> bool:
        """Fallback: Manual compilation without CMake"""
        try:
            self.log("Using fallback manual compilation...")

            # Collect all C source files
            source_files = list(self.c_methods_dir.glob("**/*.c"))
            if not source_files:
                self.log("No C source files found", "ERROR")
                return False

            self.log(f"Found {len(source_files)} C source files")

            # Determine output filename
            if self.platform_name == "windows":
                output_file = self.lib_dir / "polygottem_c.dll"
                lib_flag = "/LD"
            elif self.platform_name == "darwin":
                output_file = self.lib_dir / "libpolygottem_c.dylib"
                lib_flag = "-dynamiclib"
            else:
                output_file = self.lib_dir / "libpolygottem_c.so"
                lib_flag = "-shared"

            self.lib_dir.mkdir(parents=True, exist_ok=True)

            # Get compiler
            compiler = "cl.exe" if self.platform_name == "windows" else ("clang" if self.platform_name == "darwin" else "gcc")

            # Build compilation command
            compile_cmd = [compiler]
            if self.platform_name != "windows":
                compile_cmd.extend(["-fPIC", "-O2"])
            compile_cmd.append(lib_flag)
            compile_cmd.append(f"-I{self.c_methods_dir / 'include'}")
            compile_cmd.extend([str(f) for f in source_files])
            compile_cmd.append(f"-o{output_file}")

            self.log(f"Compiling to: {output_file}")
            result = subprocess.run(compile_cmd, capture_output=True)

            if result.returncode != 0:
                self.log(f"Compilation failed: {result.stderr.decode()}", "ERROR")
                return False

            if output_file.exists():
                self.compiled_library = str(output_file)
                self.log(f"Successfully compiled: {output_file}")
                return True
            else:
                self.log("Compilation succeeded but output file not found", "ERROR")
                return False

        except Exception as e:
            self.log(f"Manual compilation error: {e}", "ERROR")
            return False

    def compile(self) -> bool:
        """Compile C methods library"""
        self.log(f"Compiling for {self.platform_name}/{self.arch}")

        # Check compiler
        if not self.check_compiler():
            self.log("C compiler not found. Install gcc, clang, or MSVC", "ERROR")
            return False

        # Create build directory
        if not self.create_build_directory():
            return False

        # Try CMake first
        if subprocess.run(["cmake", "--version"], capture_output=True).returncode == 0:
            if self.compile_with_cmake():
                return True
            self.log("CMake compilation failed, trying manual compilation...")

        # Fallback to manual compilation
        return self.compile_manual()

    def load_library(self) -> bool:
        """Load compiled C library"""
        try:
            if not self.compiled_library:
                # Find compiled library
                if self.platform_name == "windows":
                    lib_files = list(self.lib_dir.glob("*.dll"))
                elif self.platform_name == "darwin":
                    lib_files = list(self.lib_dir.glob("*.dylib"))
                else:
                    lib_files = list(self.lib_dir.glob("*.so"))

                if not lib_files:
                    self.log("No compiled library found", "ERROR")
                    return False

                self.compiled_library = str(lib_files[0])

            self.log(f"Loading library: {self.compiled_library}")
            self.c_library = ctypes.CDLL(self.compiled_library)
            self.log("Successfully loaded C library")
            return True

        except Exception as e:
            self.log(f"Failed to load library: {e}", "ERROR")
            return False

    def get_library(self):
        """Get ctypes library object"""
        if not self.c_library:
            if not self.load_library():
                return None
        return self.c_library

    def call_function(self, function_name: str, *args):
        """Call C function from library"""
        try:
            lib = self.get_library()
            if not lib:
                self.log(f"Library not loaded", "ERROR")
                return None

            func = getattr(lib, function_name)
            result = func(*args)
            self.log(f"Called {function_name}")
            return result

        except AttributeError:
            self.log(f"Function not found: {function_name}", "ERROR")
            return None
        except Exception as e:
            self.log(f"Error calling {function_name}: {e}", "ERROR")
            return None

    def get_version(self) -> str:
        """Get C methods version"""
        try:
            lib = self.get_library()
            if not lib:
                return "unknown"

            func = lib.polygottem_c_version
            func.restype = ctypes.c_char_p
            version = func()
            return version.decode('utf-8') if version else "unknown"
        except:
            return "unknown"

    def initialize(self) -> bool:
        """Initialize C methods system"""
        try:
            lib = self.get_library()
            if not lib:
                return False

            init_func = lib.polygottem_c_init
            init_func.restype = ctypes.c_int
            result = init_func()
            self.log(f"Initialization result: {result}")
            return result == 0
        except Exception as e:
            self.log(f"Initialization failed: {e}", "ERROR")
            return False

    def cleanup(self):
        """Cleanup C methods system"""
        try:
            if self.c_library:
                cleanup_func = self.c_library.polygottem_c_cleanup
                cleanup_func()
                self.log("Cleanup complete")
        except Exception as e:
            self.log(f"Cleanup error: {e}", "ERROR")

    def build_status(self) -> Dict[str, bool]:
        """Get build status"""
        return {
            "compiler_available": self.check_compiler(),
            "build_dir_exists": self.build_dir.exists(),
            "library_compiled": self.compiled_library is not None,
            "library_loaded": self.c_library is not None,
        }


def main():
    """CLI interface for C compiler"""
    import argparse

    parser = argparse.ArgumentParser(description="POLYGOTTEM C Methods Compiler")
    parser.add_argument("--compile", action="store_true", help="Compile C methods")
    parser.add_argument("--load", action="store_true", help="Load compiled library")
    parser.add_argument("--status", action="store_true", help="Show compilation status")
    parser.add_argument("--clean", action="store_true", help="Clean build artifacts")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    compiler = PolygottemCCompiler(verbose=args.verbose)

    if args.compile:
        print("Compiling C methods library...")
        if compiler.compile():
            print("✓ Compilation successful")
        else:
            print("✗ Compilation failed")
            sys.exit(1)

    if args.load:
        print("Loading C library...")
        if compiler.load_library():
            print("✓ Library loaded successfully")
        else:
            print("✗ Failed to load library")
            sys.exit(1)

    if args.status:
        status = compiler.build_status()
        print("\nBuild Status:")
        print(f"  Compiler available: {status['compiler_available']}")
        print(f"  Build directory: {status['build_dir_exists']}")
        print(f"  Library compiled: {status['library_compiled']}")
        print(f"  Library loaded: {status['library_loaded']}")
        print(f"  Version: {compiler.get_version()}")

    if args.clean:
        print("Cleaning build artifacts...")
        if compiler.build_dir.exists():
            shutil.rmtree(compiler.build_dir)
            print("✓ Cleanup complete")

    if not any([args.compile, args.load, args.status, args.clean]):
        parser.print_help()


if __name__ == "__main__":
    main()
