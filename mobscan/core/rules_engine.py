"""
YAML Rules Engine - Interpretador de regras de vulnerabilidade em YAML

Permite criação modular de regras para detectar vulnerabilidades.
"""

import yaml
import re
import logging
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """Representa uma regra YAML"""
    id: str
    pattern: str
    severity: str
    masvs: List[str]
    description: str
    remediation: str
    test_cases: List[str]
    category: str
    cwe: List[str]


class RulesEngine:
    """Interpretador de regras YAML"""

    def __init__(self):
        self.rules: Dict[str, Rule] = {}
        self.compiled_rules: Dict[str, re.Pattern] = {}

    def load_rules_from_file(self, rules_file: str) -> List[Rule]:
        """Carrega regras de arquivo YAML"""
        try:
            with open(rules_file, 'r') as f:
                rules_data = yaml.safe_load(f)

            if not rules_data or 'rules' not in rules_data:
                logger.warning(f"No rules found in {rules_file}")
                return []

            loaded_rules = []
            for rule_data in rules_data['rules']:
                rule = self._parse_rule(rule_data)
                if rule:
                    self.rules[rule.id] = rule
                    self._compile_rule(rule)
                    loaded_rules.append(rule)

            logger.info(f"Loaded {len(loaded_rules)} rules from {rules_file}")
            return loaded_rules

        except Exception as e:
            logger.error(f"Error loading rules: {str(e)}")
            return []

    def load_rules_from_dict(self, rules_dict: Dict[str, Any]) -> List[Rule]:
        """Carrega regras de dicionário"""
        loaded_rules = []

        if 'rules' not in rules_dict:
            return loaded_rules

        for rule_data in rules_dict['rules']:
            rule = self._parse_rule(rule_data)
            if rule:
                self.rules[rule.id] = rule
                self._compile_rule(rule)
                loaded_rules.append(rule)

        return loaded_rules

    def _parse_rule(self, rule_data: Dict[str, Any]) -> Optional[Rule]:
        """Parse um rule do dicionário"""
        try:
            return Rule(
                id=rule_data.get('id', ''),
                pattern=rule_data.get('pattern', ''),
                severity=rule_data.get('severity', 'medium'),
                masvs=rule_data.get('masvs', []),
                description=rule_data.get('description', ''),
                remediation=rule_data.get('remediation', ''),
                test_cases=rule_data.get('test_cases', []),
                category=rule_data.get('category', ''),
                cwe=rule_data.get('cwe', []),
            )
        except Exception as e:
            logger.warning(f"Error parsing rule: {str(e)}")
            return None

    def _compile_rule(self, rule: Rule) -> None:
        """Compila regex pattern de uma regra"""
        try:
            pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
            self.compiled_rules[rule.id] = pattern
        except Exception as e:
            logger.warning(f"Error compiling pattern for rule {rule.id}: {str(e)}")

    def apply_rules(self, content: str) -> List[Dict[str, Any]]:
        """Aplica todas as regras carregadas ao conteúdo"""
        matches = []

        for rule_id, pattern in self.compiled_rules.items():
            rule = self.rules[rule_id]
            pattern_matches = pattern.finditer(content)

            for match in pattern_matches:
                line_number = content[:match.start()].count('\n') + 1

                matches.append({
                    'rule_id': rule.id,
                    'title': rule.description,
                    'severity': rule.severity,
                    'category': rule.category,
                    'cwe': rule.cwe,
                    'masvs': rule.masvs,
                    'remediation': rule.remediation,
                    'match': match.group(0),
                    'line': line_number,
                    'match_start': match.start(),
                    'match_end': match.end(),
                })

        return matches

    def apply_rule(self, rule_id: str, content: str) -> List[Dict[str, Any]]:
        """Aplica uma regra específica"""
        if rule_id not in self.compiled_rules:
            return []

        rule = self.rules[rule_id]
        pattern = self.compiled_rules[rule_id]
        matches = []

        pattern_matches = pattern.finditer(content)

        for match in pattern_matches:
            line_number = content[:match.start()].count('\n') + 1

            matches.append({
                'rule_id': rule.id,
                'title': rule.description,
                'severity': rule.severity,
                'category': rule.category,
                'match': match.group(0),
                'line': line_number,
            })

        return matches

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Retorna uma regra pelo ID"""
        return self.rules.get(rule_id)

    def list_rules(self) -> List[Rule]:
        """Lista todas as regras carregadas"""
        return list(self.rules.values())

    def get_rules_by_severity(self, severity: str) -> List[Rule]:
        """Retorna regras por severidade"""
        return [r for r in self.rules.values() if r.severity == severity]

    def get_rules_by_masvs(self, masvs_id: str) -> List[Rule]:
        """Retorna regras mapeadas para MASVS específico"""
        return [r for r in self.rules.values() if masvs_id in r.masvs]

    def validate_rules(self) -> Dict[str, Any]:
        """Valida integridade das regras carregadas"""
        validation = {
            'total_rules': len(self.rules),
            'valid_rules': 0,
            'invalid_rules': 0,
            'errors': []
        }

        for rule_id, rule in self.rules.items():
            if not rule.id or not rule.pattern:
                validation['invalid_rules'] += 1
                validation['errors'].append(f"Rule {rule_id} missing id or pattern")
            elif rule_id not in self.compiled_rules:
                validation['invalid_rules'] += 1
                validation['errors'].append(f"Rule {rule_id} pattern failed to compile")
            else:
                validation['valid_rules'] += 1

        return validation
