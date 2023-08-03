from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations.contract import Contract
from slither.core.declarations.function_contract import FunctionContract
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.call_expression import CallExpression
from slither.core.variables.state_variable import StateVariable
from plugin.detectors.utils import get_all_require_statements, is_protected, get_external_contracts, safe_all_expressions, require_deep_condition, get_function_signiture
from plugin.detectors.guard_check_pattern import auth_guard_condition

class OraclePattern(AbstractDetector):
    '''
    Documentation
    '''

    ARGUMENT = 'oracle'
    HELP = 'Help printed by slither'
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = 'Wiki'

    WIKI_TITLE = 'wiki title'
    WIKI_DESCRIPTION = 'wiki desc'
    WIKI_EXPLOIT_SCENARIO = 'wiki scenario'
    WIKI_RECOMMENDATION = 'wiki rec'
    
    def check_num_contracts(self):
        return len(self.slither.contracts) > 1


        
    def has_oracle_invocation_function(self, contract: Contract, potential_oracles: list[tuple[Contract, str]]):
        """
        Check if the contract has a function that invokes a function of another contract
        """
        for func in filter(lambda func: not func.is_constructor, contract.functions):
            for exp in safe_all_expressions(func):
                if isinstance(exp, CallExpression):
                    if isinstance(exp.called, MemberAccess):
                        flatten_functions: list[tuple[FunctionContract, Contract, str]] = []

                        for contract, contractVariable in potential_oracles:
                            for function in contract.functions:
                                flatten_functions.append((function, contract, contractVariable))

                        for function, contract, contractVariable in flatten_functions:
                            if function.name == exp.called.member_name and function.contract == contract:
                                return function, contract, contractVariable

        return None
    
    def has_oracle_callback_function(self, contract: Contract, potential_oracles: list[tuple[Contract, str]]):
        """
        Check if the contract has a function is protected to be invoked by oracle contract
        """
        for func in filter(lambda func: not func.is_constructor and func.visibility in ['public', 'external'] and not func.pure and not func.view and not func.payable and len(func.parameters) > 0, contract.functions):
            if is_protected(func):
                for ex in get_all_require_statements(func):
                    if require_deep_condition(ex, auth_guard_condition, func):
                        if require_deep_condition(ex, lambda arg: isinstance(arg, StateVariable) and arg.name in map(lambda x: x[1], potential_oracles), func) or self.check_for_popular_callback_names(func.name):
                           return func


        return None
    
    def check_for_popular_callback_names(self, function_name: str):
        cmp_name = function_name.lower()
        pop_callback_names = (
            'callback', # Oraclize, ProvableAPI, most other oracles
            'fulfill' # Chainlink
            )
            
        return any(map(lambda name: name in cmp_name, pop_callback_names))
            


    def _detect(self):
        info = []

        if(not self.check_num_contracts()):
            return []
        
        for contract in self.slither.contracts:
            potential_oracles = get_external_contracts(contract)
            if potential_oracles:
                invocation = self.has_oracle_invocation_function(contract, potential_oracles)
                callback = self.has_oracle_callback_function(contract, potential_oracles)
                if invocation and callback:
                    info.append(f'DETECTOR INFO: Contract {contract.name} implements the oracle pattern.\nOracle contract: {invocation[1].name}, oracle state variable: {contract.name}.{invocation[2]}\nCallback function: {get_function_signiture(callback)}\n\n')

        res = self.generate_result(info)

        if info:
            return [res]
        
        return []