package com.labmentix.phishshield.repository;

import com.labmentix.phishshield.entity.ScanHistory;
import com.labmentix.phishshield.enums.RiskLevel;
import com.labmentix.phishshield.enums.ScanType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ScanHistoryRepository extends JpaRepository<ScanHistory, Long> {

    // JOIN FETCH to avoid N+1 when listing a user's scan history with the user loaded
    @Query("select s from ScanHistory s join fetch s.user u where u.id = :userId order by s.createdAt desc")
    Page<ScanHistory> findByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId, Pageable pageable);

    @Query("select s from ScanHistory s join fetch s.user order by s.createdAt desc")
    Page<ScanHistory> findAllOrderByCreatedAtDesc(Pageable pageable);

    long countByScanType(ScanType scanType);

    long countByRiskLevel(RiskLevel riskLevel);
}
