import os
import sys


ROOT = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, ROOT)
os.chdir(ROOT)


if __name__ == "__main__":
    from launch import main

    main()