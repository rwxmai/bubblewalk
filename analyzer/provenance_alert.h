#pragma once

#include "provenance.h"
#include <string>

namespace nu {
/* Human-readable, stderr-ready text for findings already established by
 * evaluate(). An empty string means there is no provenance anomaly to show. */
std::string provenanceAlerts(const StackEvidence& evidence,const Evaluation& evaluation);
}
