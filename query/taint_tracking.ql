/**
 * @name Network data flows to memcpy size
 * @description Tracciamento del flusso dai dati di rete alla dimensione di memcpy per trovare buffer overflow.
 * @kind path-problem
 * @id cpp/uboot-network-taint-tracking
 * @problem.severity warning
 * @precision high
 * @tags security
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
