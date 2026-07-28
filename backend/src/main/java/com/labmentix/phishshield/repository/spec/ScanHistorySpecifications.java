package com.labmentix.phishshield.repository.spec;

import com.labmentix.phishshield.entity.ScanHistory;
import com.labmentix.phishshield.enums.RiskLevel;
import com.labmentix.phishshield.enums.ScanType;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDateTime;

/**
 * Each method returns a Specification that's a no-op (always-true predicate) when its
 * corresponding filter value is null, so ScanHistoryController can chain all four together
 * unconditionally and only the ones the caller actually provided end up affecting the query.
 */
public final class ScanHistorySpecifications {

    private ScanHistorySpecifications() {
    }

    public static Specification<ScanHistory> hasUserId(Long userId) {
        return (root, query, cb) ->
                userId == null ? cb.conjunction() : cb.equal(root.get("user").get("id"), userId);
    }

    public static Specification<ScanHistory> hasRiskLevel(RiskLevel riskLevel) {
        return (root, query, cb) ->
                riskLevel == null ? cb.conjunction() : cb.equal(root.get("riskLevel"), riskLevel);
    }

    public static Specification<ScanHistory> hasScanType(ScanType scanType) {
        return (root, query, cb) ->
                scanType == null ? cb.conjunction() : cb.equal(root.get("scanType"), scanType);
    }

    public static Specification<ScanHistory> createdBetween(LocalDateTime from, LocalDateTime to) {
        return (root, query, cb) -> {
            if (from == null && to == null) {
                return cb.conjunction();
            }
            if (from != null && to != null) {
                return cb.between(root.get("createdAt"), from, to);
            }
            if (from != null) {
                return cb.greaterThanOrEqualTo(root.get("createdAt"), from);
            }
            return cb.lessThanOrEqualTo(root.get("createdAt"), to);
        };
    }
}
