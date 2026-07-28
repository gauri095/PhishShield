package com.labmentix.phishshield.repository;

import com.labmentix.phishshield.entity.Report;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ReportRepository extends JpaRepository<Report, Long> {

    List<Report> findByScanHistoryId(Long scanHistoryId);
}
