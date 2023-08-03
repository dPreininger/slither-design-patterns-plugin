from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations.contract import Contract
from slither.core.declarations.modifier import Modifier
from slither.core.expressions.expression import Expression
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.state_variable import StateVariable
from plugin.detectors.utils import get_all_require_statements, is_protected, require_deep_condition, get_function_signiture, is_overriden

class EmergencyStopPattern(AbstractDetector):
    '''
    Documentation
    '''

    ARGUMENT = 'emergency-stop'
    HELP = 'Help printed by slither'
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'Wiki'

    WIKI_TITLE = 'wiki title'
    WIKI_DESCRIPTION = 'wiki desc'
    WIKI_EXPLOIT_SCENARIO = 'wiki scenario'
    WIKI_RECOMMENDATION = 'wiki rec'

    def check_for_stop_modifiers(self, contract: Contract):
        modifier_state_var_pairs = map(lambda modifier: (modifier, self.is_modifier_stop_modifier(modifier)), contract.modifiers)

        return list(filter(lambda modifier_state_var_pair: modifier_state_var_pair[1] is not None, modifier_state_var_pairs))
    
    # helper for deep condition. assigns state variable to assignment_obj if expression is a state variable of type bool to be accessed later.
    def deep_cond_helper(self, expression: Expression, assignment_obj: dict):
        result = isinstance(expression, StateVariable) and isinstance(expression.type, ElementaryType) and expression.type == ElementaryType('bool')

        if result:
            assignment_obj['state_var'] = expression

        return result

    # returns isStopped state variable name if modifier is a stop modifier
    def is_modifier_stop_modifier(self, modifier: Modifier):
        expressions = get_all_require_statements(modifier)

        if len(expressions) != 1:
            return None
        
        state_var_dict = {}

        if require_deep_condition(expressions[0], lambda x: self.deep_cond_helper(x, state_var_dict), modifier):
            return state_var_dict['state_var']
        
        return None
    
    def check_stop_modifier_application(self, contract: Contract, potential_stop_modifiers: list[tuple[Modifier, StateVariable]]):
        return list(filter(lambda modifier: self.is_stop_modifier_applied_everywhere(contract, modifier[0]), potential_stop_modifiers))

    def is_stop_modifier_applied_everywhere(self, contract: Contract, modifier: Modifier):
        public_mutable_functions = list(filter(lambda function: not function.is_constructor and function.visibility in ('public', 'external') and not function.pure and not function.view and not is_overriden(function), contract.functions))

        # if no public mutable functions, return false
        if not public_mutable_functions:
            return False

        # Set threshold for how many functions must be protected by stop modifier out of all public functions. Set 1 for all.
        THRESHOLD = 0.5

        stopable_funcs = list(filter(lambda function: modifier in function.modifiers, public_mutable_functions))
        guarded_non_stopable_funcs = list(filter(lambda function: modifier not in function.modifiers and is_protected(function), public_mutable_functions))

        # if |stopable_funcs| / (|all_functions| - |guarded_non_stopable_funcs|) >= THRESHOLD, return true
        try:
            return len(stopable_funcs) / (len(public_mutable_functions) - len(guarded_non_stopable_funcs)) >= THRESHOLD
        except ZeroDivisionError:
            return len(stopable_funcs) > 0
    
    def _detect(self):
        info = []
        
        for contract in self.slither.contracts:
            potential_stop_modifiers = self.check_for_stop_modifiers(contract)
            stop_modifiers = self.check_stop_modifier_application(contract, potential_stop_modifiers)
            for modifier, state_var in stop_modifiers:
                no_stop_functions = list(filter(lambda function: modifier not in function.modifiers and not function.is_constructor and not is_overriden(function) and not function.pure and not function.view and function.visibility in ('public', 'external'), contract.functions))
                if no_stop_functions:
                    info.append(f'DETECTOR INFO: Emergency Stop Pattern detected in Contract {contract.name}.\nModifier {modifier.name} implements this pattern using state variable {contract.name}.{state_var.name}.\nThe following public mutable functions are not guarded by emergency stop modifier: {", ".join([get_function_signiture(func) for func in no_stop_functions])}\n\n')
                else:
                    info.append(f'DETECTOR INFO: Emergency Stop Pattern detected in Contract {contract.name}.\nModifier {modifier.name} implements this pattern using state variable {contract.name}.{state_var.name}.\n\n')


        res = self.generate_result(info)

        if info:
            return [res]
        
        return []