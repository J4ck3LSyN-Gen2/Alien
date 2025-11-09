from typing import Dict, Any, Optional, List

__version__ = "0.0.1"

class syntaxInlineExecFalseWithNoProgramData(Exception):

    """
    Root: core.interpreterHandle.run
    """

    def __init__(self):

        self.message = "Inline data was found however `runInline` argument was false, with no programData loaded."
        super().__ini__(self.message)

class syntaxCannotRunWithNoProgramData(Exception):

    """
    Root: core.interpreterHandle.run
    """

    def __init__(self):

        self.message = "`run()` was called while no programData was loaded nor inline statements."
        super().__init__(self.message)

class syntaxTryCatchMissingKeys(Exception):

    """
    Root: core.interpreterHandle._handleTryCatch
    """

    def __init__(self,
                 statement:Dict[str,Any]):
        self.statement = statement
        self.message = f"Statement (try/catch) is missing the 'try' statements.. Nothing to try.."
        super().__init__(self.message)
        

class syntaxStatementAssignMissingKeys(Exception):

    """
    Root: core.interpreterHandle._handleStatements
    """

    def __init__(self,
                 statement:Dict[str,Any]):
        self.statement = statement
        self.message = f"Statement (assign) is missing `target` and/or `value` key(s), statement: {str(statement)}"
        super().__init__(self.message)

class syntaxExpressionIndexAccessMissingKeys(Exception):

    """
    Root: core.interpreterHandle._handleExpression
    """

    def __init__(self,
                 expression:Dict[str,Any]):
        self.expression = expression
        self.message = f"Expression (indexAccess) is missing 'container' and/or 'index' key(s)."
        super().__init__(self.message)

class syntaxExpressionNewClassNameIsNonExistant(Exception):

    """
    Root: core.interpreterHandle._handleExpression
    """

    def __init__(self,
                 expression:Dict[str,Any],
                 className:str):
        self.expression = expression
        self.message = f"Expression (new) `className`({str(className)}) is non-existant inside of classes. Expression: {str(expression)}"
        super().__init__(self.message)

class syntaxExpressionNewMissingClassName(Exception):

    """
    Root: core.interpreterHandle._handlExpression
    """
    
    def __init__(self,
                 expression:Dict[str,Any]):
        self.expression = expression
        self.message = f"Expression (new) is missing the 'className' key: {str(expression)}"
        super().__init__(self.message)

class syntaxExpressionMethodCallMissingTargetKey(Exception):

    """
    Root: core.interpreterHandle._handleExpression
    """

    def __init__(self,
                 expression:Dict[str,Any]):
        self.expression = expression
        self.message = f"Expression (methodCall) is missing 'target' key: {str(expression)}"
        super().__init__(self.message)


class syntaxExpressionCallMissingFunctionNameKey(Exception):

    """
    Root: core.interpreterHandle._handleExpression
    """

    def __init__(self,
                 expression:Dict[str,Any]):
        self.expression = expression
        self.message = f"Expression with `call` type is missing the 'functionName' key: {str(expression)}"
        super().__init__(self.message)

class syntaxFunctionNotCallable(Exception):
    
    """
    root: core.interpreterHandle._handleFunctionCall

    If Function Is Not Callable.
    """

    def __init__(self,
                 functionName:str):
        self.functionName = functionName
        self.message = f"Function '{str(functionName)}' is not callable."
        super().__init__(self.message)

class syntaxFunctionMissingRequiredArgument(Exception):

    """
    Root: core.interpreterHandle._handleFunctionCall

    If Function Is Missing Required Parameter.
    """

    def __init__(self,
                 functionName:str,
                 parameterName:str):
        self.functionName = functionName
        self.parameterName = parameterName
        self.message = f"Function '{str(functionName)}' is missing required argument '{str(parameterName)}'"
        super().__init__(self.message)

class syntaxFunctionParameterMissingNameKey(Exception):

    """
    Root: core.interpreterHandle._handleFunctionCall

    If Function Parameter Is Missing The 'name' Key.

    Example Parameter:
        [
            {
                'name':str
            }
        ]
    """

    def __init__(self,
                 functionName:str,
                 parameter:Dict[str,Any],
                 extendedMessage:str=None):
        self.functionName = str(functionName)
        self.parameter = parameter
        self.message = f"Function '{str(functionName)}' parameter '{str(parameter)}' is missing the 'name' key."
        if extendedMessage: self.message += f" Extended message: {str(extendedMessage)}"
        super().__init__(self.message)

class syntaxFunctionFailedToResolve(Exception):

    """
    Root: core.interpreterHandle._handleFunctionCall

    If The `functionName` Did Not Resolve An Execution Object.
    """

    def __init__(self,
                 functionName:str):

        self.functionName = str(functionName)
        self.message = f"Function '{str(functionName)}' failed to resolve an executable object."
        super().__init__(str(self.message))

class syntaxIfStatementMissingKeys(Exception):

    """
    Root: core.interpreterHandle._handleStatements

    If Statement (if) Is Missing The `conditoin` And/Or `then` Key(s).
    """

    def __init__(self,
                 statement:Dict,
                 extendedMessage:str=None):
        self.statement = statement
        self.message = f"Statement (if) is missing the `condition` and/or `then` key(s). "
        if extendedMessage: self.message += f"Extended information (possible `elseif` failure): {str(extendedMessage)}"
        super().__init__(str(self.message))

class syntaxExitCodeNotInt(Exception):
    
    """
    Root: core.interpreterHandle._exit

    If Argument 'statusCode' Was Not int.
    """

    def __init__(self,exceptionCode:Any):

        self.exceptionCode = exceptionCode
        self.message = f"Exit was called but is not an 'int' type, got: {str(type(exceptionCode).__name__)}"
        super().__init__(str(self.message))

class syntaxCannotResolveVariableDueToNonExistance(Exception):

    """
    Root: core.interpreter._varResolve

    If A Variable Name Was Not Resolved.
    """

    def __init__(self,name:str):

        self.name = str(name)
        self.message = f"Failed to find '{str(name)}' due to non-existance."
        super().__init__(str(self.message))

class syntaxCannotEvalDueToMissingValueKey(Exception):

    """
    Root: core.interpreterHandle.*

    If 'value' Is Missing From Objects That Require It.
    """

    def __init__(self,object:Dict):

        self.object = object
        self.message = f"Statement/Expression object is missing the 'value' key."
        super().__init__(str(self.message))

## Binary Operations

class syntaxBinaryOpMissingLeftOrRight(Exception):

    def __init__(self,
                 expression:Dict,
                 operator:str):
        self.expression = expression
        self.operator = operator
        self.message = f"Binary operation '{str(operator)}' is missing either 'left' or 'right' values(expressions)."
        super().__init__(str(self.message))



class syntaxBinaryOpMissingValues(Exception):

    """
    Root: core.interpreterHandle._handleExpression

    If 'operator' Is mIssing.
    """

    def __init__(self,
                 expression:str):
        self.expression = expression
        self.message = f"Binary operation missing the 'operator' key."
        super().__init__(str(self.message))

class syntaxBinaryOpInvalidOperator(Exception):

    """
    Root: core.interpreterHandle._handleBinaryOp

    If The 'operand' For Binary Operations Is Invalid.
    """

    def __init__(self,
                 operatorGiven:str,
                 operatorsAvailable:List[str]):
        self.operatorGiven = str(operatorGiven)
        self.operatorsAvailable = operatorsAvailable
        self.message(f"Operator '{str(operatorGiven)}' does not exist... Available Keys: {str(' :: ').join(operatorsAvailable)}")
        super().__init__(str(self.message))

class syntaxTypeKeyMissing(Exception):

    """
    Root: core.interpreterHandle.(_handleStatements,_handleExpression)

    If 'type' Key Is Missing From A Statement.
    """

    def __init__(self,objectMissingType:Dict,**extendedContext):

        self.objectMissingType = objectMissingType
        self.extendedContext   = extendedContext if extendedContext else {}

        self.contextMessage = str(" :: ").join([f"{k}:{v}" for k,v in extendedContext.items()])
        self.message = f"Object '{str(objectMissingType)}' is missing the `type` key... {str(self.extendedContext)}"
        super().__init__(str(self.message))

class syntaxInvalidExpressionType(Exception):

    """
    Root: core.interpreterHandle._handleExpression

    If Expression 'type' Is Invalid.
    """

    def __init__(self,
                 expression:Dict,
                 typeKeyGiven:str):
        self.expression = expression
        self.typeKeyGiven = typeKeyGiven
        self.message = f"Expression '{str(expression)}' has an invalid type({str(typeKeyGiven)})"
        super().__init__(str(self.message))

class syntaxInvalidStatementType(Exception):
    
    """
    Root: core.interpreterHandle._handleStatements

    If The Statement Type Was Invalid
    """

    def __init__(self,
                 originalStatements:List[Dict[str,Any]],
                 statementThatFailed:Dict[str,Any],
                 statementTypeGiven:str,
                 statementFailureIndex:int):
        self.originalStatements = originalStatements
        self.statementThatFailed = statementThatFailed
        self.statementTypeGiven = statementTypeGiven
        self.statementFailureIndex = statementFailureIndex
        self.message = f"Statement {str(statementFailureIndex)} has an invalid type({str(statementTypeGiven)}):: Original statements: {str(originalStatements)} :: Statement that failed: {str(statementThatFailed)}"
        super().__init__(str(self.message))