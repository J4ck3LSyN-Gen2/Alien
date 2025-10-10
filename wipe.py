import os
import shutil
from pathlib import Path

def wipe_paths(base_path: Path, paths_to_wipe: list[str]):
    """
    Iterates through a list of relative paths, checks if they exist,
    and removes them. Handles both files and directories.

    Args:
        base_path (Path): The root path from which relative paths are resolved.
        paths_to_wipe (list[str]): A list of relative paths to delete.
    """
    print(f"Starting wipe process from base directory: {base_path}\n")

    for relative_path_str in paths_to_wipe:
        # It's good practice to resolve the path against a base to avoid accidents.
        target_path = base_path.joinpath(relative_path_str).resolve()
        
        print(f"Processing: {target_path}")

        try:
            if not target_path.exists():
                print(f"  - SKIPPED: Path does not exist.\n")
                continue

            if target_path.is_dir():
                print(f"  - Path is a directory. Deleting recursively...")
                shutil.rmtree(target_path)
                print(f"  - SUCCESS: Directory deleted.\n")
            elif target_path.is_file():
                print(f"  - Path is a file. Deleting...")
                os.remove(target_path)
                print(f"  - SUCCESS: File deleted.\n")
            else:
                # This could be a broken symlink or other special file type
                print(f"  - SKIPPED: Path is not a regular file or directory.\n")

        except PermissionError:
            print(f"  - FAILED: Permission denied. Could not delete {target_path}.\n")
        except Exception as e:
            print(f"  - FAILED: An unexpected error occurred: {e}\n")

if __name__ == "__main__":
    paths_to_clean = [
        "ALNv2020/__pycache__",
        "ALNv2020/utils/__pycache__",
        "ALNv2020/libs/__pycache__",
        "ALNv2020/logs/"
    ]

    current_directory = Path.cwd()
    wipe_paths(current_directory, paths_to_clean)

    print("Wipe process complete.")