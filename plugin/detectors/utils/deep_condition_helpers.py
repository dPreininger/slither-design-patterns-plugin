from slither.core.declarations.function_contract import FunctionContract
from slither.core.declarations.solidity_variables import SolidityVariableComposed
from slither.core.expressions.call_expression import CallExpression
from slither.core.expressions.expression import Expression
from slither.core.expressions.identifier import Identifier
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.unary_operation import UnaryOperation
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from typing import Callable

class LocalContext:
    def __init__(self, function: FunctionContract):
        self.state_variables = function.contract.state_variables_ordered
        self.local_variables = function.local_variables
        self.function_parameters = function.parameters
        self.contract_functions = function.contract.functions

# condition is a function that takes in expression and returns a boolean
class DeepCondition:
    _context: LocalContext = None

    def __init__(self, condition: Callable[[Identifier | LocalVariable | StateVariable], bool], context_function: FunctionContract):
        self._context_function = context_function
        self.condition = condition

    def does_expression_satisfy_condition(self, expression: Expression):
        return self.recursive_iteration(expression)
        
    def recursive_iteration(self, expression: Expression):
        if expression is None:
            return False

        if isinstance(expression, UnaryOperation):
            return self.recursive_iteration(expression.expression)
        if isinstance(expression, BinaryOperation):
            return self.recursive_binary_operation(expression)
        if isinstance(expression, Identifier) or isinstance(expression, SolidityVariableComposed):
            return self.recursive_identifier(expression)
        if isinstance(expression, LocalVariable):
            return self.recursive_local_variable(expression)
        if isinstance(expression, StateVariable):
            return self.recursive_state_variable(expression)
        if isinstance(expression, CallExpression):
            return self.recursive_call(expression)
        
        return False

    def recursive_binary_operation(self, expression: BinaryOperation):
        return self.recursive_iteration(expression.expression_right) or self.recursive_iteration(expression.expression_left)

    def recursive_identifier(self, expression: Identifier | SolidityVariableComposed):
        variable = self.get_variable_from_identifier(expression)

        if variable is None:
            return self.condition(expression)
            
        return self.recursive_iteration(variable)
    
    def recursive_local_variable(self, expression: LocalVariable):
        if self.condition(expression):
            return True
        
        return self.recursive_iteration(expression.expression)
    
    def recursive_state_variable(self, expression: StateVariable):
        if self.condition(expression):
            return True
        
        return self.recursive_iteration(expression.expression)
    
    def recursive_call(self, expression: CallExpression):
        func = self.get_function_from_call(expression)

        if func is None or not func.return_values:
            return False
        
        return any([self.recursive_iteration(x) for x in func.return_values])

    @property
    def context(self):
        if self._context is not None:
            return self._context
        
        return self.build_context()
        

    def build_context(self):
        self._context = LocalContext(self._context_function)

        return self._context

    def get_variable_from_identifier(self, identifier: Identifier | SolidityVariableComposed):
        state_var = next(filter(lambda x: x.name == str(identifier), self.context.state_variables), None)
        if state_var:
            return state_var
        
        local_var = next(filter(lambda x: x.name == str(identifier), self.context.local_variables), None)
        if local_var:
            return local_var
        
        function_param = next(filter(lambda x: x.name == str(identifier), self.context.function_parameters), None)
        if function_param:
            return function_param
        
        return None
    
    def get_function_from_call(self, expression: CallExpression):
        return next(filter(lambda x: x.name == str(expression.called), self.context.contract_functions), None)
