from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations.function_contract import FunctionContract
from slither.core.expressions.identifier import Identifier
from slither.core.declarations.solidity_variables import SolidityVariableComposed
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from plugin.detectors.utils import get_all_require_statements, is_deployable, require_deep_condition, get_function_signiture, is_overriden

class GuardCheckPattern(AbstractDetector):
    '''
    Documentation
    '''

    ARGUMENT = 'guard-check'
    HELP = 'Help printed by slither'
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'Wiki'

    WIKI_TITLE = 'wiki title'
    WIKI_DESCRIPTION = 'wiki desc'
    WIKI_EXPLOIT_SCENARIO = 'wiki scenario'
    WIKI_RECOMMENDATION = 'wiki rec'

    def check_for_auth_guard(self, function: FunctionContract):
        if function.is_constructor:
            return False

        require_statements = get_all_require_statements(function)

        return list(filter(lambda req_statement: require_deep_condition(req_statement, auth_guard_condition, function), require_statements))
    
    def check_for_state_guard(self, function: FunctionContract):
        if function.is_constructor:
            return False

        require_statements = get_all_require_statements(function)

        return list(filter(lambda req_statement: require_deep_condition(req_statement, lambda x: isinstance(x, StateVariable), function), require_statements))
    
    def check_for_arg_guard(self, function: FunctionContract):
        if function.is_constructor:
            return False
        
        require_statements = get_all_require_statements(function)

        return list(filter(lambda req_statement: require_deep_condition(req_statement, lambda x: isinstance(x, LocalVariable) and x.name in [param.name for param in function.parameters], function), require_statements))

    def _detect(self):
        info = []
        
        for contract in self.slither.contracts:
            for func in filter(lambda f: not f.is_constructor and not is_overriden(f), contract.functions):

                auth_guards = self.check_for_auth_guard(func)
                state_guards = self.check_for_state_guard(func)
                arg_guards = self.check_for_arg_guard(func)

                has_guards = bool(auth_guards or state_guards or arg_guards)

                info.append(f'DETECTOR INFO: Function {get_function_signiture(func)} has {len(auth_guards) if auth_guards else 0} Auth Guard Patterns, {len(state_guards) if state_guards else 0} State Guard Patterns and {len(arg_guards) if arg_guards else 0} Input Guard Patterns.\n\n')

                if auth_guards:
                    info.append(f'DETECTOR INFO: Auth Guard Pattern detected in function {get_function_signiture(func)}.\nExpressions implementing this pattern: {", ".join([str(ex) for ex in auth_guards])}\n\n')

                if state_guards:
                    info.append(f'DETECTOR INFO: State Guard Pattern detected in function {get_function_signiture(func)}.\nExpressions implementing this pattern: {", ".join([str(ex) for ex in state_guards])}\n\n')

                if arg_guards:
                    info.append(f'DETECTOR INFO: Input Guard Pattern detected in function {get_function_signiture(func)}.\nExpressions implementing this pattern: {", ".join([str(ex) for ex in arg_guards])}\n\n')

                if not has_guards and func.visibility in ('public', 'external') and is_deployable(func.contract):
                    info.append(f'DETECTOR WARNING: No Guard Patterns detected in {func.visibility} function {get_function_signiture(func)}.\n\n')

        res = self.generate_result(info)

        if info:
            return [res]
        
        return []
    

def auth_guard_condition(x):
    if isinstance(x, Identifier):
        return x.value.name == 'msg.sender'
    elif isinstance(x, SolidityVariableComposed):
        return x.name == 'msg.sender'
    return False