#!/usr/bin/env python3
"""
VeriGuard Build Script

Usage:
    ./build.py                          # Build (default)
    ./build.py build                    # Build Ada crates and ESP-IDF firmware
    ./build.py clean                    # Clean both Ada crates and ESP-IDF
    ./build.py clean build              # Chain: clean then build
    ./build.py build --idf monitor      # Build, then run idf.py monitor
    ./build.py build --idf -p /dev/ttyUSB0 flash  # Build, then flash to specific port
    ./build.py build --alr --release    # Build with --release flag to alr

Flags:
    --alr <args...>     Pass arguments to alr build/clean commands
    --idf <args...>     Pass arguments to idf.py after build/clean
"""

import os
import sys
import subprocess
from pathlib import Path

# Configuration
SCRIPT_DIR = Path(__file__).parent.absolute()
ADA_CRATES = ["crypto", "wireguard", "net", "bindings"]
VALID_COMMANDS = {"build", "clean"}


def check_idf_path():
    """Verify IDF_PATH environment variable is set."""
    if not os.environ.get("IDF_PATH"):
        print("ERROR: IDF_PATH not set. Run: source /opt/esp-idf/export.sh")
        sys.exit(1)


def run_command(cmd, cwd=None, description=""):
    """Execute a shell command with output streamed to terminal."""
    try:
        if description:
            print(f"\n  {description}...")
        
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd or SCRIPT_DIR,
        )
        
        return result.returncode == 0
    except Exception as e:
        print(f"ERROR: {e}")
        return False


def run_command_interactive(cmd, cwd=None, description=""):
    """Execute a shell command interactively (output to terminal)."""
    try:
        if description:
            print(f"\n{description}...\n")
        
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd or SCRIPT_DIR,
        )
        
        return result.returncode == 0
    except Exception as e:
        print(f"ERROR: {e}")
        return False


def clean_ada_crates(alr_args=""):
    """Clean all Ada crates."""
    print("\n[1/2] Cleaning Ada crates with Alire...")
    all_success = True
    
    for crate in ADA_CRATES:
        crate_dir = SCRIPT_DIR / crate
        cmd = f"alr clean {alr_args}".strip()
        if not run_command(cmd, cwd=crate_dir, description=f"Cleaning {crate}"):
            all_success = False
    
    return all_success


def clean_idf(idf_args=""):
    """Clean ESP-IDF build."""
    print("\n[2/2] Cleaning ESP-IDF firmware...")
    cmd = f"idf.py fullclean {idf_args}".strip()
    return run_command(cmd, description="Cleaning ESP-IDF")


def build_ada_crates(alr_args=""):
    """Build all Ada crates."""
    print("\n[1/2] Building Ada crates with Alire...")
    all_success = True
    
    for crate in ADA_CRATES:
        crate_dir = SCRIPT_DIR / crate
        cmd = f"alr build --release {alr_args}".strip()
        if not run_command(cmd, cwd=crate_dir, description=f"Building {crate}"):
            all_success = False
    
    return all_success


def build_idf(idf_args=""):
    """Build ESP-IDF firmware."""
    print("\n[2/2] Building ESP-IDF firmware...")
    cmd = f"idf.py build {idf_args}".strip()
    return run_command(cmd, description="Building firmware")


def execute_command(cmd, alr_args="", idf_args=""):
    """Execute a single command."""
    if cmd == "clean":
        return clean_ada_crates(alr_args) and clean_idf(idf_args)
    elif cmd == "build":
        return build_ada_crates(alr_args) and build_idf(idf_args)
    else:
        return False


def execute_idf_command(idf_args):
    """Execute a standalone idf.py command interactively."""
    cmd = f"idf.py {idf_args}".strip()
    return run_command_interactive(cmd, description="Running idf.py")


def print_header(title):
    """Print a formatted header."""
    print("\n" + "=" * 42)
    print(f"{title.center(42)}")
    print("=" * 42)


def print_footer(success):
    """Print a formatted footer."""
    print("\n" + "=" * 42)
    if success:
        print(f"{'Build Complete!'.center(42)}")
        print(f"{'Firmware: build/VeriGuard.elf'.center(42)}")
    else:
        print(f"{'Build Failed!'.center(42)}")
    print("=" * 42 + "\n")


def main():
    """Main entry point."""
    check_idf_path()
    
    # Parse arguments - flags apply only to commands that follow them
    args = sys.argv[1:]
    
    if not args:
        args = ["build"]
    
    commands = []  # List of (command, alr_args, idf_args)
    idf_command_after = ""
    
    i = 0
    current_alr_args = ""
    current_idf_args = ""
    
    while i < len(args):
        arg = args[i]
        
        if arg == "--alr":
            # Collect alr args until --idf or next command
            alr_parts = []
            i += 1
            while i < len(args) and args[i] not in VALID_COMMANDS and args[i] != "--idf":
                alr_parts.append(args[i])
                i += 1
            current_alr_args = " ".join(alr_parts)
            continue
        
        elif arg == "--idf":
            # Collect all remaining args as idf args
            idf_parts = []
            i += 1
            while i < len(args):
                idf_parts.append(args[i])
                i += 1
            idf_command_after = " ".join(idf_parts)
            break
        
        elif arg in VALID_COMMANDS:
            # Add command with current flag context
            commands.append((arg, current_alr_args, current_idf_args))
            # Reset alr args for next command (but keep idf args if any)
            current_alr_args = ""
            i += 1
        
        else:
            print(f"ERROR: Unknown argument '{arg}'")
            print(f"\nUsage: {Path(__file__).name} [command ...] [--alr args...] [--idf args...]")
            print("\nValid commands: build, clean")
            print("\nExamples:")
            print(f"  {Path(__file__).name} build")
            print(f"  {Path(__file__).name} clean build --alr --release")
            print(f"  {Path(__file__).name} build --idf monitor")
            print(f"  {Path(__file__).name} clean build --alr --release --idf monitor")
            sys.exit(1)
    
    if not commands:
        commands = [("build", "", "")]
    
    # Determine action description
    action = " → ".join(cmd[0] for cmd in commands)
    extra = ""
    if idf_command_after:
        extra = f" → idf.py {idf_command_after}"
    
    print_header(f"VeriGuard {action.title()}{extra}")
    
    # Execute commands in sequence
    success = True
    for cmd, alr_args, idf_args in commands:
        if not execute_command(cmd, alr_args, idf_args):
            success = False
            break
    
    # Execute idf.py command if specified
    if success and idf_command_after:
        if not execute_idf_command(idf_command_after):
            success = False
    
    print_footer(success)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

