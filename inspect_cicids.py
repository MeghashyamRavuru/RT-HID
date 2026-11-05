import csv
import sys
from pathlib import Path
from collections import Counter

if len(sys.argv) != 2:
    print('Usage: python inspect_cicids.py "path/to/dataset"')
    raise SystemExit(1)

dataset_dir = Path(sys.argv[1])

if not dataset_dir.is_dir():
    print(f"Directory not found: {dataset_dir}")
    raise SystemExit(1)

csv_files = sorted(dataset_dir.rglob("*.csv"))

if not csv_files:
    print("No CSV files found.")
    raise SystemExit(1)

print(f"Found {len(csv_files)} CSV files")

for file_path in csv_files:
    print(f"\n{'=' * 70}")
    print(f"File: {file_path.name}")

    try:
        with file_path.open(
            "r", encoding="utf-8-sig", errors="replace", newline=""
        ) as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                print("No headers found.")
                continue

            print("\nColumns:")
            print([name.strip() for name in reader.fieldnames])

            label_column = next(
                (name for name in reader.fieldnames
                 if name.strip().lower() == "label"),
                None
            )

            if label_column is None:
                print("\nLabel column not found.")
                continue

            labels = Counter()
            total_rows = 0

            for row in reader:
                label = (row.get(label_column) or "").strip()
                if label:
                    labels[label] += 1
                total_rows += 1

            print(f"\nTotal rows: {total_rows:,}")
            print("Label distribution:")
            for label, count in labels.most_common():
                print(f"  {label}: {count:,}")

    except Exception as error:
        print(f"Error reading file: {error}")
