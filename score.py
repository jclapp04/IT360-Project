import csv
import glob
import os
import sys

if len(sys.argv) > 1:
    path = sys.argv[1]
else:
    sheets = glob.glob("review_*.csv")
    if not sheets:
        print("No review sheet found. Run main.py with --ai first.")
        sys.exit(1)
    path = max(sheets, key=os.path.getmtime)
print("Scoring", path)

with open(path, encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

verdicts = [r["verdict"].strip().lower() for r in rows]
done = [v for v in verdicts if v in ("correct", "partial", "incorrect")]
if not done:
    print("No verdicts filled in yet. Put correct, partial or incorrect in the verdict column.")
    sys.exit(1)

correct = done.count("correct")
partial = done.count("partial")
print(f"Reviewed {len(done)} of {len(rows)} findings")
print(f"correct {correct}, partial {partial}, incorrect {done.count('incorrect')}")
print(f"Accuracy (correct only): {100 * correct / len(done):.0f}%")
print(f"Accuracy (partial = half): {100 * (correct + partial / 2) / len(done):.0f}%")
