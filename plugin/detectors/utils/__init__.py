from slither.detectors.abstract_detector import AbstractDetector
from slither.core.declarations.contract import Contract
from slither.core.declarations.function_contract import FunctionContract
from slither.core.declarations.function import Function
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.expressions.assignment_operation import AssignmentOperation, AssignmentOperationType
from slither.core.expressions.call_expression import CallExpression
from slither.core.expressions.expression import Expression
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.declarations.solidity_variables import SolidityVariableComposed
from slither.core.expressions.identifier import Identifier
from plugin.detectors.utils.deep_condition_helpers import DeepCondition
from plugin.detectors.utils.all_expression_helpers import explore_functions
from typing import Callable

def get_all_require_statements(function: FunctionContract) -> list[CallExpression]:
    return list(filter(lambda f: isinstance(f, CallExpression) and str(f).startswith('require'), safe_all_expressions(function)))

def is_protected(function: FunctionContract):
    if function.is_constructor:
        return False

    require_statements = get_all_require_statements(function)

    cond = DeepCondition(lambda x: (isinstance(x, SolidityVariableComposed) or isinstance(x, Identifier)) and str(x) == 'msg.sender', function)
    return any(map(lambda require_statement: cond.does_expression_satisfy_condition(require_statement.arguments[0]), require_statements))

def get_external_contracts(contract: Contract) -> list[tuple[Contract, str]]:
    exContracts = []

    for state_var in contract.state_variables_ordered:
        if isinstance(state_var.type, UserDefinedType) and isinstance(state_var.type.type, Contract):
            exContracts.append((state_var.type.type, state_var.name))
        
    return exContracts

def require_deep_condition(require_expression: CallExpression, condition: Callable[[Identifier | LocalVariable | StateVariable | SolidityVariableComposed], bool], context_function: FunctionContract):
    cond = DeepCondition(condition, context_function)

    return cond.does_expression_satisfy_condition(require_expression.arguments[0])

def deep_condition(expression: Expression, condition: Callable[[Identifier | LocalVariable | StateVariable | SolidityVariableComposed], bool], context_function: FunctionContract):
    cond = DeepCondition(condition, context_function)

    return cond.does_expression_satisfy_condition(expression)

def safe_all_expressions(function: Function):
    try:
        # Official implementations
        # This implementation is faster than our own
        return function.all_expressions()
    except:
        # Use our own implementation as fallback
        # Official implementation crashes if type Literal (unhashable type) is used due to the use of sets for deduplication
        exps = explore_functions(function)
        function._all_expressions = exps
        return exps
    
def get_function_signiture(function: FunctionContract):
    return f'{function.contract.name}.{function.name}({", ".join([f"{param.type} {param.name}" for param in function.parameters])})'

def find_fist_parent_that_declares_function(function: FunctionContract, start_contract: Contract):
    queue = [start_contract]
    queue.extend(start_contract.inheritance)

    for contract in queue:
        if function.name in map(lambda f: f.name, filter(lambda f: f.is_declared_by(contract), contract.functions)):
            return contract
    
    return None

def is_overriden(function: FunctionContract):
    if function.is_declared_by(function.contract):
        return False
    
    if len(list(filter(lambda f: f.full_name == function.full_name, function.contract.functions))) == 1:
        return False

    first_declarer = find_fist_parent_that_declares_function(function, function.contract)

    return first_declarer and function.contract_declarer.name != first_declarer.name

def is_deployable(contract: Contract):
    return not contract.is_interface and not contract.is_library and contract.is_fully_implemented
