"""
Knowledge Layer — ModTester
Testing methodologies, attack playbooks, ASVS, and MASVS.
"""

from .methodology import METHODOLOGY
from .playbooks import PLAYBOOKS, match_playbooks

# Full ASVS (5 categories)
from .asvs import get_all_tests as get_asvs_tests
from .asvs import get_coverage_summary as get_asvs_summary
from .asvs import get_checklist_text as get_asvs_checklist

# MASVS (2 categories — network + auth)
from .masvs import get_all_tests as get_masvs_tests
from .masvs import get_coverage_summary as get_masvs_summary
