/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(MacroInvocation inv | inv.getMacroName() in ["ntohs", "ntohl", "ntohll"] and this = inv.getExpr())
    }
}

module MyConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap
    }

    predicate isSink(DataFlow::Node sink) {
        exists(FunctionCall call |
            call.getTarget().getName() = "memcpy" and
            sink.asExpr() = call.getArgument(2)
        )
    
        
    }

}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink)
select sink, source, sink, "network byte swap flows to memcpy"
