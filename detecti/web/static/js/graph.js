/**
 * DetecTI-CLI EASM Dashboard - Cytoscape.js Graph Implementation
 */

class EASMDashboard {
    constructor() {
        this.cy = null;
        this.graphData = null;
        this.leads = [];
        this.selectedLeads = new Set();
        this.filters = {
            matrix3d: false,
            kev: false,
            highEpss: false,
            critical: false,
            hideLowInfo: false,
            nucleiOnly: false,
            withPocs: false,
            servicesOnly: false,
            verifiedServicesOnly: false,
            vulnServicesOnly: false
        };
        this.searchTerm = '';
        this.expandedClusters = new Set();
        this.manualCollapsedClusters = new Set();
        this._hasRunInitialLayout = false;
        
        // Target Management & Active Scan State
        this.markedTargets = new Set();
        this.targetStatuses = {};
        this.scanPollingInterval = null;
        this.currentPortPreset = 'top100';
        
        // Don't auto-initialize, wait for DOM
    }

    getAvailableLayout() {
        return 'hierarchical-topdown';
    }

    computeSemanticHierarchicalPositions(targetElements = null, isLeftRight = false) {
        if (!this.cy) return {};
        const elements = targetElements || this.cy.elements(':visible');
        const nodes = elements.nodes ? elements.nodes() : elements.filter('node');
        if (nodes.length === 0) return {};

        const positions = {};
        
        // Semantic Tier Buckets
        const t0_root = [];
        const t1_domains = [];
        const t2_subdomains = [];
        const t3_ips = [];
        const t4_services = [];
        const t5_vulns = [];

        nodes.forEach(node => {
            const data = node.data();
            const type = data.type;
            if (type === 'target' || data.id === 'target_root' || data.is_root === true) t0_root.push(node);
            else if (type === 'domain') t1_domains.push(node);
            else if (type === 'subdomain') t2_subdomains.push(node);
            else if (type === 'ip' || type === 'network') t3_ips.push(node);
            else if (['service', 'http', 'https', 'cluster_services'].includes(type)) t4_services.push(node);
            else if (['vulnerability', 'cluster_vulns'].includes(type)) t5_vulns.push(node);
            else t3_ips.push(node);
        });

        const sortByResolvedIp = (a, b) => {
            const getIpId = (n) => {
                const target = n.outgoers('edge[label="RESOLVES_TO"], edge[label="IPS_HISTORY"]').targets().first();
                return target.length > 0 ? target.id() : n.id();
            };
            return getIpId(a).localeCompare(getIpId(b));
        };
        t1_domains.sort(sortByResolvedIp);
        t2_subdomains.sort(sortByResolvedIp);

        const getParentId = (node, edgeLabels) => {
            let parent = node.incomers(`edge[label="${edgeLabels.join('"], edge[label="')}"]`).sources().first();
            if (parent.length === 0) parent = node.incomers('node').first();
            return parent.length > 0 ? parent.id() : null;
        };

        const childrenMap = {}; 
        const addChild = (pid, node) => {
            if (!childrenMap[pid]) childrenMap[pid] = [];
            childrenMap[pid].push(node);
        };

        t2_subdomains.forEach(n => { const pid = getParentId(n, ["HAS_SUBDOMAIN", "MATCHES_DOMAIN"]); if(pid) addChild(pid, n); });
        t3_ips.forEach(n => { const pid = getParentId(n, ["RESOLVES_TO", "IPS_HISTORY", "CONTAINS_IP"]); if(pid) addChild(pid, n); });
        t4_services.forEach(n => {
            let parent = n.incomers('node[type="ip"]').first();
            if (parent.length === 0) parent = n.incomers('node').first();
            if (parent.length > 0) addChild(parent.id(), n);
        });
        t5_vulns.forEach(n => {
            let parent = n.incomers('node').first();
            if (parent.length > 0) addChild(parent.id(), n);
        });

        const heightCache = {};
        const getRequiredHeight = (node) => {
            if (heightCache[node.id()]) return heightCache[node.id()];
            
            const children = childrenMap[node.id()] || [];
            if (children.length === 0) {
                heightCache[node.id()] = 180;
                return 180;
            }
            
            const rows = 10;
            const rowHeights = new Array(rows).fill(0);
            children.forEach((c, idx) => {
                const r = idx % rows;
                rowHeights[r] = Math.max(rowHeights[r], getRequiredHeight(c));
            });
            
            let totalHeight = rowHeights.reduce((sum, h) => sum + h, 0);
            totalHeight += (Math.min(children.length, rows) - 1) * 20;
            
            heightCache[node.id()] = Math.max(180, totalHeight);
            return heightCache[node.id()];
        };

        // Calculate dynamic max columns to create STRICT global Tier X boundaries
        const getMaxCols = (nodes) => {
            let maxChildren = 0;
            nodes.forEach(n => {
                const cCount = childrenMap[n.id()] ? childrenMap[n.id()].length : 0;
                maxChildren = Math.max(maxChildren, cCount);
            });
            return Math.max(1, Math.ceil(maxChildren / 10));
        };
        
        const t1_cols = Math.max(1, Math.ceil(t1_domains.length / 10));
        const t2_cols = getMaxCols(t1_domains);
        const t3_cols = getMaxCols(t2_subdomains);
        const t4_cols = getMaxCols(t3_ips);

        const X_SPACINGS = {
            t1: 280,
            t2: 0,
            t3: 0, 
            t4: 0,
            t5: 0
        };
        X_SPACINGS.t2 = X_SPACINGS.t1 + (t1_cols * 350) + 150;
        X_SPACINGS.t3 = X_SPACINGS.t2 + (t2_cols * 350) + 150;
        X_SPACINGS.t4 = X_SPACINGS.t3 + (t3_cols * 350) + 150;
        X_SPACINGS.t5 = X_SPACINGS.t4 + (t4_cols * 350) + 150;

        const getNextTierX = (currentTierX) => {
            if (currentTierX === X_SPACINGS.t1) return X_SPACINGS.t2;
            if (currentTierX === X_SPACINGS.t2) return X_SPACINGS.t3;
            if (currentTierX === X_SPACINGS.t3) return X_SPACINGS.t4;
            if (currentTierX === X_SPACINGS.t4) return X_SPACINGS.t5;
            return currentTierX + 400;
        };

        const visitedPlace = new Set();
        const placeChildren = (parentId, children, baseX, tierX, xOffset = 0) => {
            if (!children || children.length === 0) return;
            if (visitedPlace.has(parentId)) return;
            visitedPlace.add(parentId);
            
            // Sort: unresolved first, resolved last
            children.sort((a, b) => {
                const countA = childrenMap[a.id()] ? childrenMap[a.id()].length : 0;
                const countB = childrenMap[b.id()] ? childrenMap[b.id()].length : 0;
                if (countA === 0 && countB > 0) return -1;
                if (countA > 0 && countB === 0) return 1;
                return a.id().localeCompare(b.id());
            });
            
            const rows = 10;
            const rowHeights = new Array(rows).fill(0);
            children.forEach((c, idx) => {
                const r = idx % rows;
                rowHeights[r] = Math.max(rowHeights[r], getRequiredHeight(c));
            });
            
            const totalHeight = rowHeights.reduce((sum, h) => sum + h, 0) + (Math.min(children.length, rows) - 1) * 20;
            const parentY = positions[parentId] ? positions[parentId].y : 0;
            let currentY = parentY - (totalHeight / 2);
            
            const rowStartYs = new Array(rows).fill(0);
            let yAccumulator = currentY;
            for(let r=0; r<rows; r++) {
                if (rowHeights[r] === 0) continue;
                rowStartYs[r] = yAccumulator + (rowHeights[r] / 2);
                yAccumulator += rowHeights[r] + 20;
            }
            
            const nextGlobalTierX = getNextTierX(tierX);

            children.forEach((c, idx) => {
                let cCol = Math.floor(idx / rows);
                const cRow = idx % rows;
                
                let x = tierX + xOffset + (cCol * 350);
                const y = rowStartYs[cRow];
                
                if (!positions[c.id()]) {
                    positions[c.id()] = { x, y };
                    placeChildren(c.id(), childrenMap[c.id()], x, nextGlobalTierX, xOffset + (cCol * 350));
                }
            });
        };

        let globalY = 0;
        t1_domains.forEach(d => getRequiredHeight(d));
        t1_domains.forEach(d => {
            const h = getRequiredHeight(d);
            const y = globalY + (h / 2);
            positions[d.id()] = { x: X_SPACINGS.t1, y };
            globalY += h + 100;
            placeChildren(d.id(), childrenMap[d.id()], X_SPACINGS.t1, X_SPACINGS.t2);
        });

        // Orphans
        [t2_subdomains, t3_ips, t4_services, t5_vulns].forEach((tierList, tierIdx) => {
            const defaultX = Object.values(X_SPACINGS)[tierIdx + 1] || (X_SPACINGS.t5 + 400);
            const nextX = Object.values(X_SPACINGS)[tierIdx + 2] || (defaultX + 400);
            tierList.forEach(node => {
                if (!positions[node.id()]) {
                    const h = getRequiredHeight(node);
                    positions[node.id()] = { x: defaultX, y: globalY + (h / 2) };
                    globalY += h + 50;
                    placeChildren(node.id(), childrenMap[node.id()], defaultX, nextX);
                }
            });
        });

        // TARGET_ROOT CENTERING
        let minY = Infinity;
        let maxY = -Infinity;
        Object.values(positions).forEach(p => {
            minY = Math.min(minY, p.y);
            maxY = Math.max(maxY, p.y);
        });
        const centerY = (minY === Infinity) ? 0 : (minY + maxY) / 2;

        t0_root.forEach((node) => {
            positions[node.id()] = { x: 0, y: centerY };
        });

        if (isLeftRight) {
            return positions;
        }

        const topDownPositions = {};
        for (const [nodeId, pos] of Object.entries(positions)) {
            topDownPositions[nodeId] = { x: pos.y, y: pos.x };
        }
        
        return topDownPositions;
    }


    getLayoutOptions(layoutName, targetElements = null) {
        const baseOptions = {
            animate: true,
            animationDuration: 550,
            animationEasing: 'ease-out',
            fit: true,
            padding: 30
        };

        const visibleCount = targetElements && typeof targetElements.nodes === 'function' 
            ? targetElements.nodes().length 
            : (this.cy ? this.cy.nodes(':visible').length : 50);

        switch (layoutName) {
            case 'breadthfirst': // Legacy fallback
            case 'hierarchical-topdown':
            case 'hierarchical-leftright':
                const isLeftRight = layoutName === 'hierarchical-leftright';
                const computedPositions = this.computeSemanticHierarchicalPositions(targetElements, isLeftRight);
                return {
                    ...baseOptions,
                    name: 'preset',
                    positions: computedPositions,
                    fit: true,
                    padding: 40
                };
            case 'cose-bilkent':
                return {
                    ...baseOptions,
                    name: 'cose-bilkent',
                    animate: 'end',
                    animationDuration: 550,
                    animationEasing: 'ease-out',
                    nodeRepulsion: visibleCount < 25 ? 1200 : (visibleCount < 60 ? 1800 : 2500),
                    idealEdgeLength: visibleCount < 25 ? 40 : 50,
                    edgeElasticity: 0.35,
                    nestingFactor: 0.1,
                    gravity: 0.5,
                    numIter: 1000,
                    coolingFactor: 0.95,
                    tile: true,
                    tilingPaddingVertical: 6,
                    tilingPaddingHorizontal: 6
                };
            case 'cose':
                return {
                    ...baseOptions,
                    name: 'cose',
                    animate: 'end',
                    animationDuration: 550,
                    animationEasing: 'ease-out',
                    nodeRepulsion: visibleCount < 25 ? 15000 : (visibleCount < 60 ? 25000 : 45000),
                    idealEdgeLength: visibleCount < 25 ? 35 : 45,
                    edgeElasticity: 80,
                    nestingFactor: 1.2,
                    gravity: 120,
                    numIter: 500
                };
            case 'concentric':
                return {
                    ...baseOptions,
                    name: 'concentric',
                    concentric: function(node) {
                        return node.degree();
                    },
                    levelWidth: function(nodes) {
                        return 2;
                    },
                    spacingFactor: 0.55,
                    minNodeSpacing: 20,
                    padding: 25
                };
            case 'grid':
                return {
                    ...baseOptions,
                    name: 'grid',
                    padding: 25,
                    avoidOverlap: true,
                    avoidOverlapPadding: 10,
                    rows: undefined,
                    cols: undefined
                };
            default:
                return baseOptions;
        }
    }

    async init() {
        try {
            console.log('Initializing EASM Dashboard...');
            
            // Set loading timeout
            const loadingTimeout = setTimeout(() => {
                console.error('Dashboard initialization timeout');
                this.showError('Dashboard loading timeout - please refresh the page');
            }, 30000); // 30 second timeout
            
            // Check if API client is available
            if (!window.api) {
                throw new Error('API client not available');
            }
            
            // Load databases list
            console.log('Loading databases list...');
            await this.loadDatabases();

            // Load summary data
            console.log('Loading summary data...');
            await this.loadSummary();
            
            // Initialize Cytoscape
            console.log('Initializing Cytoscape...');
            this.initCytoscape();
            
            // Setup Target Management & Load Targets FIRST so markedTargets is populated
            console.log('Setting up Target Management...');
            this.setupTargetManagement();
            await this.loadTargets();

            // Load and render graph (now populateLeadSelector will see markedTargets)
            console.log('Loading graph data...');
            await this.loadGraph();
            
            // Setup event listeners
            console.log('Setting up event listeners...');
            this.setupEventListeners();
            
            // Set the correct default layout in the selector
            this.updateLayoutSelector();
            
            // Clear timeout since we succeeded
            clearTimeout(loadingTimeout);
            
            // Hide loading indicator
            const loadingEl = document.getElementById('graph-loading');
            if (loadingEl) {
                loadingEl.style.display = 'none';
            }
            
            // Initialize / re-render Lucide icons
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }

            console.log('Dashboard initialization complete');
            
        } catch (error) {
            console.error('Failed to initialize dashboard:', error);
            this.showError(`Failed to load dashboard data: ${error.message}`);
            
            // Emergency fallback: Show basic lead selector even if API fails
            this.showEmergencyLeadSelector();
        }
    }

    async loadSummary() {
        try {
            console.log('Fetching summary data...');
            const summary = await window.api.getSummary();
            console.log('Summary data received:', summary);
            
            // Update header
            const targetEl = document.getElementById('target-name');
            if (targetEl) {
                targetEl.textContent = summary.target || 'Unknown Target';
            }
            
            // Update metrics with safe element access
            const updateMetric = (id, value) => {
                const el = document.getElementById(id);
                if (el) {
                    el.textContent = value || 0;
                } else {
                    console.warn(`Element not found: ${id}`);
                }
            };
            
            updateMetric('domains-count', summary.total_domains);
            updateMetric('subdomains-count', summary.total_subdomains);
            updateMetric('ips-count', summary.total_ips);
            updateMetric('services-count', summary.open_services);
            updateMetric('verified-services-count', summary.verified_services !== undefined ? summary.verified_services : 0);
            updateMetric('vulns-count', summary.total_vulnerabilities);
            updateMetric('kev-count', summary.cisa_kev_count);
            updateMetric('epss-count', summary.high_epss_count !== undefined ? summary.high_epss_count : 0);
            
            console.log('Summary data loaded successfully');
            
        } catch (error) {
            console.error('Failed to load summary:', error);
            throw error; // Re-throw to be caught by init()
        }
    }

    populateLeadSelector(elements, preserveSelection = false) {
        try {
            console.log('=== LEAD SELECTOR DEBUG START ===');
            console.log('Populating lead selector from graph data...');
            this.leads = [];
            
            const leadList = document.getElementById('lead-list');
            if (!leadList) {
                console.error('Lead list element not found');
                return;
            }
            
            // Clear loading message immediately
            leadList.innerHTML = '<div class="lead-loading">Processing targets...</div>';
            
            // Try to get elements from Cytoscape if not provided
            if (!elements && this.cy) {
                console.log('Getting elements from Cytoscape instance...');
                const cyNodes = this.cy.nodes().jsons();
                const cyEdges = this.cy.edges().jsons();
                elements = {
                    nodes: cyNodes,
                    edges: cyEdges
                };
                console.log(`Got ${cyNodes.length} nodes and ${cyEdges.length} edges from Cytoscape`);
            }
            
            if (!elements || !elements.nodes || !Array.isArray(elements.nodes)) {
                console.warn('No valid graph elements available for lead selector');
                leadList.innerHTML = '<div class="lead-loading">No graph data available</div>';
                return;
            }
            
            console.log(`Total nodes in graph: ${elements.nodes.length}`);
            console.log(`Total edges in graph: ${elements.edges ? elements.edges.length : 0}`);
            
            // Debug: Log first few nodes to see structure
            console.log('First 3 nodes structure:', elements.nodes.slice(0, 3));
            

            // 1. Look for pre-calculated explore_leads data from the backend
            const rootNode = elements.nodes.find(n => (n.data || n).id === 'target_root');
            const rootData = rootNode ? (rootNode.data || rootNode) : null;
            
            if (rootData && rootData.explore_leads && Array.isArray(rootData.explore_leads)) {
                console.log(`Using pre-calculated explore_leads from backend: ${rootData.explore_leads.length} leads`);
                this.leads = rootData.explore_leads.map(lead => ({
                    id: lead.id,
                    label: lead.label,
                    display_name: lead.display_name || lead.label,
                    type: lead.type,
                    vuln_count: lead.vuln_count || 0,
                    service_count: lead.service_count || 0,
                    verified_service_count: lead.verified_service_count || 0,
                    kev_count: lead.kev_count || 0,
                    has_kev: lead.has_kev || false,
                    critical_count: lead.critical_count || 0,
                    has_critical: (lead.critical_count || 0) > 0,
                    high_count: lead.high_count || 0,
                    poc_count: lead.poc_count || 0,
                    max_epss: lead.max_epss || 0,
                    high_epss_count: lead.high_epss_count || 0,
                    three_d_score: lead.three_d_score || 0,
                    is_target: false // Explicit target state handled separately
                }));
            } else {

            // 1. Look for pre-calculated explore_leads data from the backend
            const rootNode = elements.nodes.find(n => (n.data || n).id === 'target_root');
            const rootData = rootNode ? (rootNode.data || rootNode) : null;
            
            if (rootData && rootData.explore_leads && Array.isArray(rootData.explore_leads)) {
                console.log(`Using pre-calculated explore_leads from backend: ${rootData.explore_leads.length} leads`);
                this.leads = rootData.explore_leads.map(lead => {
                    const matchedNode = elements.nodes.find(n => (n.data || n).id === lead.id);
                    const isTarget = matchedNode ? ((matchedNode.data || matchedNode).is_target === true || (matchedNode.data || matchedNode).is_target === 'true') : false;
                    
                    if (isTarget) {
                        console.log(`[DEBUG] Matched Target Lead: ${lead.id} | TargetName: ${lead.display_name || lead.label}`);
                    }
                    
                    return {
                        id: lead.id,
                        label: lead.label,
                        display_name: lead.display_name || lead.label,
                        type: lead.type,
                        vuln_count: lead.vuln_count || 0,
                        service_count: lead.service_count || 0,
                        verified_service_count: lead.verified_service_count || 0,
                        kev_count: lead.kev_count || 0,
                        has_kev: lead.has_kev || false,
                        critical_count: lead.critical_count || 0,
                        has_critical: (lead.critical_count || 0) > 0,
                        high_count: lead.high_count || 0,
                        poc_count: lead.poc_count || 0,
                        max_epss: lead.max_epss || 0,
                        high_epss_count: lead.high_epss_count || 0,
                        three_d_score: lead.three_d_score || 0,
                        is_target: isTarget
                    };
                });
            } else {
                console.warn('explore_leads data not found, falling back to graph traversal...');
                let leadNodes = elements.nodes.filter(node => {
                    const nodeData = node.data || node;
                    const nodeType = nodeData.type;
                    return ['ip', 'domain', 'subdomain'].includes(nodeType);
                });
                if (leadNodes.length === 0) leadNodes = elements.nodes.slice();
                if (leadNodes.length === 0) {
                    leadList.innerHTML = `<div class="lead-loading" style="color: #ff4757;">No lead nodes found in database.</div>`;
                    return;
                }
                
                leadNodes.forEach((node, index) => {
                    try {
                        const nodeData = node.data || node;
                        const connectedVulns = this.findConnectedVulnerabilities(nodeData.id, elements);
                        const connectedServices = this.findConnectedServices(nodeData.id, elements);
                        
                        const vulnCount = connectedVulns.length;
                        const kevVulns = connectedVulns.filter(v => v.is_cisa_kev === true || v.is_cisa_kev === 'true' || v.is_cisa_kev === 1);
                        const kevCount = kevVulns.length;
                        const criticalVulns = connectedVulns.filter(v => String(v.severity || '').toUpperCase() === 'CRITICAL');
                        const criticalCount = criticalVulns.length;
                        const highVulns = connectedVulns.filter(v => String(v.severity || '').toUpperCase() === 'HIGH');
                        const highCount = highVulns.length;
                        const pocCount = connectedVulns.reduce((sum, v) => sum + ((v.exploits && v.exploits.length) || v.exploit_count || 0 > 0 ? ((v.exploits && v.exploits.length) || v.exploit_count || 0) : 0), 0);
                        let maxEpss = 0.0;
                        let highEpssCount = 0;
                        connectedVulns.forEach(v => {
                            const epss = parseFloat(v.epss_score) || 0.0;
                            if (epss > maxEpss) maxEpss = epss;
                            if (epss >= 0.20) highEpssCount++;
                        });
                        const serviceCount = connectedServices.length;
                        const verifiedServiceCount = connectedServices.filter(s => s.verified_active === true || s.verified === true || s.status === 'active' || s.verified_active === 1).length;
                        
                        const threeDScore = (kevCount * 1000000) + (pocCount * 200000) + (highEpssCount * 100000) + (maxEpss * 50000) + (criticalCount * 50000) + (highCount * 20000) + (verifiedServiceCount * 5000) + (vulnCount * 1000) + (serviceCount * 100);
                        let displayName = nodeData.type === 'ip' && nodeData.ip ? nodeData.ip : (nodeData.label || nodeData.name || nodeData.ip || nodeData.id);
                        
                        this.leads.push({
                            id: nodeData.id,
                            label: nodeData.label || nodeData.id,
                            display_name: displayName,
                            type: nodeData.type || 'unknown',
                            vuln_count: vulnCount,
                            service_count: serviceCount,
                            verified_service_count: verifiedServiceCount,
                            kev_count: kevCount,
                            has_kev: kevCount > 0,
                            critical_count: criticalCount,
                            has_critical: criticalCount > 0,
                            high_count: highCount,
                            poc_count: pocCount,
                            max_epss: maxEpss,
                            high_epss_count: highEpssCount,
                            three_d_score: threeDScore,
                            is_target: nodeData.is_target === true,
                            node: nodeData
                        });
                    } catch (err) {
                        console.error('Error processing lead node:', node, err);
                    }
                });
            }
            }
            
            // FINAL FALLBACK: If still no leads after processing, force create from raw data
            if (this.leads.length === 0 && elements.nodes.length > 0) {
                console.warn('FINAL FALLBACK: Force creating leads from raw node data...');
                elements.nodes.forEach((node, index) => {
                    try {
                        const nodeData = node.data || node;
                        console.log(`Force lead ${index + 1}: ${nodeData.id} (${nodeData.type})`);
                        
                        // Create a more descriptive display name
                        let displayName = nodeData.label || nodeData.name || nodeData.ip || nodeData.id;
                        if (nodeData.ip) {
                            displayName = nodeData.ip;
                        } else if (nodeData.label && nodeData.label.includes('\n')) {
                            // Extract first line for display
                            displayName = nodeData.label.split('\n')[0];
                        }
                        
                        const lead = {
                            id: nodeData.id,
                            type: nodeData.type || 'unknown',
                            name: nodeData.name || nodeData.ip || nodeData.label || nodeData.id,
                            display_name: displayName,
                            org: nodeData.org || 'Unknown',
                            country: nodeData.country || 'Unknown',
                            service_count: 0,
                            vuln_count: 0,
                            has_kev: false,
                            has_critical: false,
                            poc_count: 0,
                            ip_count: 0
                        };
                        
                        this.leads.push(lead);
                        console.log(`✓ Force lead created: ${lead.display_name}`);
                    } catch (error) {
                        console.error(`Error creating force lead ${index}:`, error);
                    }
                });
            }
            
            // Reset lead selection on initial database load (leads come unchecked by default)
            // But preserve active leads when refreshing after a background scan
            if (!preserveSelection) {
                this.selectedLeads.clear();
                
                // Auto-select leads that are explicitly marked as targets (via CLI or backend)
                let hydratedTargets = false;
                this.leads.forEach(lead => {
                    if (lead.is_target) {
                        const targetName = lead.display_name || lead.label;
                        if (targetName && !this.markedTargets.has(targetName)) {
                            this.markedTargets.add(targetName);
                            hydratedTargets = true;
                        }
                    }
                    
                    if (this.isTargetMarked(lead.display_name || lead.label)) {
                        this.selectedLeads.add(lead.id);
                    }
                });
                
                if (hydratedTargets) {
                    this.renderTargetsList();
                }
                // If no targets were selected from backend, fallback to Tier 1
                if (this.selectedLeads.size === 0) {
                    const tier1Leads = this.leads.filter(l => l.is_tier1);
                    if (tier1Leads.length > 0 && tier1Leads.length <= 50) {
                        tier1Leads.forEach(lead => this.selectedLeads.add(lead.id));
                    }
                }
            } else {
                const currentLeadIds = new Set(this.leads.map(l => l.id));
                Array.from(this.selectedLeads).forEach(id => {
                    if (!currentLeadIds.has(id)) {
                        this.selectedLeads.delete(id);
                    }
                });
            }

            console.log(`✓ Created ${this.leads.length} leads total (preserveSelection: ${preserveSelection})`);
            console.log('=== LEAD SELECTOR DEBUG END ===');
            
            // Always try to render, even if we have 0 leads
            this.renderLeadSelector();
            
        } catch (error) {
            console.error('❌ CRITICAL ERROR in populateLeadSelector:', error);
            console.error('Error stack:', error.stack);
            const leadList = document.getElementById('lead-list');
            if (leadList) {
                leadList.innerHTML = `
                    <div class="lead-loading" style="color: #ff4757;">
                        ⚠️ Error loading leads: ${error.message}
                        <br><small>Check console for details</small>
                        <br><button onclick="location.reload()" style="margin-top: 10px; padding: 5px 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer;">Reload Page</button>
                    </div>
                `;
            }
        }
    }
    
    buildGraphIndex(elements) {
        this.nodeIndex = new Map();
        this.outEdges = new Map();
        this.inEdges = new Map();

        if (!elements || !elements.nodes) return;

        elements.nodes.forEach(node => {
            const data = node.data || node;
            if (data && data.id) {
                this.nodeIndex.set(data.id, data);
            }
        });

        if (elements.edges) {
            elements.edges.forEach(edge => {
                const data = edge.data || edge;
                if (!data) return;
                
                if (data.source) {
                    if (!this.outEdges.has(data.source)) this.outEdges.set(data.source, []);
                    this.outEdges.get(data.source).push(data);
                }
                if (data.target) {
                    if (!this.inEdges.has(data.target)) this.inEdges.set(data.target, []);
                    this.inEdges.get(data.target).push(data);
                }
            });
        }
    }

    findConnectedIPs(nodeId, elements) {
        if (!elements || !elements.edges) return [];
        if (!this.nodeIndex) this.buildGraphIndex(elements);

        const targetData = this.nodeIndex.get(nodeId);
        if (!targetData) return [];
        if (targetData.type === 'ip') return [targetData];

        const connectedIpIds = new Set();
        const visitedSubIds = new Set();
        const visitedDomIds = new Set();

        const outEdges = this.outEdges.get(nodeId) || [];
        const inEdges = this.inEdges.get(nodeId) || [];

        if (targetData.type === 'target' || targetData.type === 'network') {
            outEdges.forEach(edgeData => {
                if (edgeData.label === 'MATCHES_DOMAIN' || edgeData.label === 'CONTAINS_TARGET') {
                    const tgtNode = this.nodeIndex ? this.nodeIndex.get(edgeData.target) : null;
                    if (tgtNode && tgtNode.type === 'ip') {
                        connectedIpIds.add(edgeData.target);
                    } else if (tgtNode && tgtNode.type === 'subdomain') {
                        visitedSubIds.add(edgeData.target);
                    } else {
                        visitedDomIds.add(edgeData.target);
                    }
                }
                if (edgeData.label === 'CONTAINS_IP' || edgeData.label === 'HOSTS_IP' || edgeData.label === 'RESOLVES_TO' || edgeData.label === 'IPS_HISTORY') {
                    connectedIpIds.add(edgeData.target);
                }
            });
            inEdges.forEach(edgeData => {
                if (edgeData.label === 'BELONGS_TO' || edgeData.label === 'ORGANIZATION_OF') {
                    connectedIpIds.add(edgeData.source);
                }
            });
        }

        if (targetData.type === 'domain') {
            visitedDomIds.add(nodeId);
        }

        visitedDomIds.forEach(domId => {
            const domOut = this.outEdges.get(domId) || [];
            const domIn = this.inEdges.get(domId) || [];

            domOut.forEach(edgeData => {
                if (edgeData.label === 'HAS_SUBDOMAIN' || edgeData.label === 'CONTAINS_SUBDOMAIN') {
                    visitedSubIds.add(edgeData.target);
                }
                if (edgeData.label === 'HOSTS_IP' || edgeData.label === 'CONTAINS_IP' || edgeData.label === 'RESOLVES_TO' || edgeData.label === 'IPS_HISTORY') {
                    connectedIpIds.add(edgeData.target);
                }
            });
            domIn.forEach(edgeData => {
                if (edgeData.label === 'BELONGS_TO') {
                    visitedSubIds.add(edgeData.source);
                }
            });
        });

        // Recursively traverse downstream subdomains and find their resolved IPs
        const processSubdomainTree = (subId, visitedSubs = new Set()) => {
            if (visitedSubs.has(subId)) return;
            visitedSubs.add(subId);

            const subOut = this.outEdges.get(subId) || [];
            subOut.forEach(edgeData => {
                if (edgeData.label === 'RESOLVES_TO' || edgeData.label === 'IPS_HISTORY' || edgeData.label === 'CONTAINS_IP' || edgeData.label === 'HOSTS_IP') {
                    connectedIpIds.add(edgeData.target);
                }
                if (edgeData.label === 'HAS_SUBDOMAIN' || edgeData.label === 'CONTAINS_SUBDOMAIN') {
                    processSubdomainTree(edgeData.target, visitedSubs);
                }
            });
        };

        if (targetData.type === 'subdomain') {
            processSubdomainTree(nodeId);
        }

        visitedSubIds.forEach(subId => {
            processSubdomainTree(subId);
        });

        const ipNodes = [];
        connectedIpIds.forEach(ipId => {
            const ipData = this.nodeIndex.get(ipId);
            if (ipData && ipData.type === 'ip') {
                ipNodes.push(ipData);
            }
        });
        return ipNodes;
    }

    filterVulnsByActiveFilters(vulnList) {
        if (!Array.isArray(vulnList)) return [];
        if (!this.filters) return vulnList;

        const hasFilters = this.filters.matrix3d || this.filters.kev || this.filters.highEpss || 
                           this.filters.critical || this.filters.hideLowInfo || this.filters.nucleiOnly || this.filters.withPocs;
        if (!hasFilters) return vulnList;

        return vulnList.filter(v => {
            const severity = String(v.severity || '').toUpperCase();
            const source = String(v.source || '').toLowerCase();

            if (this.filters.matrix3d) {
                // Dimensão 1: Direct Active Service Traceability
                let hasActiveService = false;
                if (this.inEdges && v.id) {
                    const inEdges = this.inEdges.get(v.id) || [];
                    hasActiveService = inEdges.some(e => {
                        if (e.label === 'HAS_VULN') {
                            const srv = this.nodeIndex ? this.nodeIndex.get(e.source) : null;
                            if (srv && ['service', 'http', 'https'].includes(srv.type)) {
                                return srv.verified_active === true || srv.is_active_scan === true;
                            }
                        }
                        return false;
                    });
                }
                if (!hasActiveService && this.cy && v.id) {
                    const vNode = this.cy.getElementById(v.id);
                    if (vNode.length > 0) {
                        const parentServices = vNode.incomers('node[type="service"], node[type="http"], node[type="https"]');
                        hasActiveService = parentServices.some(srv => {
                            const sData = srv.data();
                            return sData.verified_active === true || sData.is_active_scan === true;
                        });
                    }
                }
                if (!hasActiveService) return false;

                // Dimensão 2: Technical Severity
                const cvss = parseFloat(v.cvss_score || 0);
                const hasTechImpact = severity === 'CRITICAL' || severity === 'HIGH' || (severity === 'MEDIUM' && cvss >= 5.0) || cvss >= 6.5;
                if (!hasTechImpact) return false;

                // Dimensão 3: Real-World Threat
                const isKev = v.is_cisa_kev === true || v.is_cisa_kev === 'true' || v.is_cisa_kev === 1;
                const epss = parseFloat(v.epss_score || 0);
                const hasPocs = v.has_pocs === true || (Array.isArray(v.exploits) && v.exploits.length > 0) || (parseInt(v.exploit_count || 0) > 0);
                const realWorldThreat = isKev || (epss >= 0.2) || hasPocs;
                if (!realWorldThreat) return false;
            }

            if (this.filters.kev) {
                if (v.is_cisa_kev !== true && v.is_cisa_kev !== 1) return false;
            }
            if (this.filters.highEpss) {
                const epssScore = parseFloat(v.epss_score || 0);
                if (epssScore <= 0.5) return false;
            }
            if (this.filters.critical) {
                if (severity !== 'CRITICAL') return false;
            }
            if (this.filters.hideLowInfo) {
                if (severity === 'LOW' || severity === 'INFO' || severity === 'UNKNOWN') return false;
            }
            if (this.filters.nucleiOnly) {
                if (!source.includes('nuclei')) return false;
            }
            if (this.filters.withPocs) {
                const hasPocs = v.has_pocs === true || (Array.isArray(v.exploits) && v.exploits.length > 0);
                if (!hasPocs) return false;
            }
            return true;
        });
    }

    findDirectVulnerabilities(nodeId, elements) {
        if (!elements || !elements.edges) return [];
        if (!this.nodeIndex) this.buildGraphIndex(elements);

        const vulnerabilities = [];
        const nodeOut = this.outEdges.get(nodeId) || [];
        nodeOut.forEach(edgeData => {
            if (edgeData.label === 'HAS_VULN') {
                const vulnData = this.nodeIndex.get(edgeData.target);
                if (vulnData && vulnData.type === 'vulnerability') {
                    vulnerabilities.push(vulnData);
                }
            }
        });
        const filtered = this.filterVulnsByActiveFilters(vulnerabilities);
        return this.sortVulnsBy3DRiskMatrix(filtered);
    }

    sortVulnsBy3DRiskMatrix(vulnList) {
        if (!Array.isArray(vulnList)) return [];

        const getSevWeight = (sev) => {
            const s = String(sev || '').toUpperCase();
            if (s === 'CRITICAL') return 50000;
            if (s === 'HIGH') return 30000;
            if (s === 'MEDIUM') return 15000;
            if (s === 'LOW') return 5000;
            return 1000;
        };

        const calculate3DScore = (v) => {
            let score = 0;

            // 1. CISA KEV (Known Exploited Vulnerability - Flag máxima de prioridade P1 / Weaponized in the Wild)
            const isKev = v.is_cisa_kev === true || v.is_cisa_kev === 'true' || v.is_cisa_kev === 1;
            if (isKev) {
                score += 1000000;
            }

            // 2. PoC Weaponization Index (ExploitDB / GitHub Functional PoCs)
            const expCount = (v.exploits && v.exploits.length) || v.exploit_count || 0;
            if (expCount > 0) {
                score += 200000 + Math.min(expCount, 5) * 10000;
            }

            // 3. FIRST EPSS Probability (0.0 to 1.0 -> 0% to 100%)
            const epss = parseFloat(v.epss_score) || 0.0;
            if (epss >= 0.20) {
                score += 100000; // Bonus for reaching 3D Matrix threshold
            }
            score += epss * 50000;

            // 4. Nominal Severity & CVSS Score Base
            score += getSevWeight(v.severity);
            const cvss = parseFloat(v.cvss_score) || 0.0;
            score += cvss * 1000;

            return score;
        };

        return [...vulnList].sort((a, b) => {
            const scoreB = calculate3DScore(b);
            const scoreA = calculate3DScore(a);
            if (scoreB !== scoreA) {
                return scoreB - scoreA;
            }
            // Tie-breaker: Alphabetical CVE
            const cveA = (a.cve_id || a.name || a.label || '').toUpperCase();
            const cveB = (b.cve_id || b.name || b.label || '').toUpperCase();
            return cveA.localeCompare(cveB);
        });
    }

    findConnectedVulnerabilities(nodeId, elements) {
        if (!elements || !elements.edges) return [];
        if (!this.nodeIndex) this.buildGraphIndex(elements);

        const vulnerabilities = [];
        const selfData = this.nodeIndex.get(nodeId);
        if (selfData && selfData.type === 'vulnerability') {
            const filtered = this.filterVulnsByActiveFilters([selfData]);
            return filtered;
        }

        try {
            if (selfData && selfData.vuln_ids) {
                const vulns = selfData.vuln_ids.map(id => this.nodeIndex.get(id)).filter(Boolean);
                const filtered = this.filterVulnsByActiveFilters(vulns);
                return this.sortVulnsBy3DRiskMatrix(filtered);
            }
            // 1. Find all vulnerabilities via connected services (Service -> Vulnerability)
            const connectedServices = this.findConnectedServices(nodeId, elements);
            connectedServices.forEach(service => {
                const srvOut = this.outEdges.get(service.id) || [];
                srvOut.forEach(edgeData => {
                    if (edgeData.label === 'HAS_VULN') {
                        const vulnData = this.nodeIndex.get(edgeData.target);
                        if (vulnData && vulnData.type === 'vulnerability') {
                            vulnerabilities.push(vulnData);
                        }
                    }
                });
            });
            
            // 2. Find all vulnerabilities directly connected to IPs (IP -> Vulnerability)
            const connectedIPs = this.findConnectedIPs(nodeId, elements);
            connectedIPs.forEach(ipData => {
                const ipOut = this.outEdges.get(ipData.id) || [];
                ipOut.forEach(edgeData => {
                    if (edgeData.label === 'HAS_VULN') {
                        const vulnData = this.nodeIndex.get(edgeData.target);
                        if (vulnData && vulnData.type === 'vulnerability') {
                            vulnerabilities.push(vulnData);
                        }
                    }
                });
            });

            // 3. Check direct vulnerability connections from nodeId itself
            const nodeOut = this.outEdges.get(nodeId) || [];
            nodeOut.forEach(edgeData => {
                if (edgeData.label === 'HAS_VULN') {
                    const vulnData = this.nodeIndex.get(edgeData.target);
                    if (vulnData && vulnData.type === 'vulnerability') {
                        vulnerabilities.push(vulnData);
                    }
                }
            });
            
            if (selfData && selfData.passive_vulns && Array.isArray(selfData.passive_vulns)) {
                selfData.passive_vulns.forEach(vuln => vulnerabilities.push(vuln));
            }
            
            // Remove duplicates by CVE ID or ID
            const seenCveKeys = new Set();
            const uniqueVulns = [];
            vulnerabilities.forEach(v => {
                const cveKey = (v.cve_id || v.label || v.name || v.id || '').trim().toUpperCase();
                if (cveKey && cveKey !== 'UNKNOWN') {
                    if (!seenCveKeys.has(cveKey)) {
                        seenCveKeys.add(cveKey);
                        uniqueVulns.push(v);
                    }
                } else if (!uniqueVulns.some(uv => uv.id === v.id)) {
                    uniqueVulns.push(v);
                }
            });
            
            const filteredVulns = this.filterVulnsByActiveFilters(uniqueVulns);
            return this.sortVulnsBy3DRiskMatrix(filteredVulns);
        } catch (error) {
            console.error('Error in findConnectedVulnerabilities:', error);
            return [];
        }
    }
    
    findConnectedServices(nodeId, elements) {
        if (!elements || !elements.edges) return [];
        if (!this.nodeIndex) this.buildGraphIndex(elements);

        const services = [];
        const selfData = this.nodeIndex.get(nodeId);
        if (selfData && ['service', 'http', 'https'].includes(selfData.type)) {
            return [selfData];
        }

        try {
            if (selfData && selfData.service_ids) {
                return selfData.service_ids.map(id => this.nodeIndex.get(id)).filter(Boolean);
            }
            // Find services connected FROM this node (IP/domain exposes services)
            const nodeOut = this.outEdges.get(nodeId) || [];
            nodeOut.forEach(edgeData => {
                if (edgeData.label === 'EXPOSES') {
                    const srvData = this.nodeIndex.get(edgeData.target);
                    if (srvData && ['service', 'http', 'https'].includes(srvData.type)) {
                        services.push(srvData);
                    }
                }
            });
            
            // Also find services that belong to this node (reverse direction)
            const nodeIn = this.inEdges.get(nodeId) || [];
            nodeIn.forEach(edgeData => {
                if (edgeData.label === 'BELONGS_TO') {
                    const srvData = this.nodeIndex.get(edgeData.source);
                    if (srvData && ['service', 'http', 'https'].includes(srvData.type)) {
                        services.push(srvData);
                    }
                }
            });

            // If node is a target, organization, domain or subdomain, find all connected IPs and their exposed services
            const connectedIPs = this.findConnectedIPs(nodeId, elements);
            connectedIPs.forEach(ipData => {
                const ipOut = this.outEdges.get(ipData.id) || [];
                ipOut.forEach(edgeData => {
                    if (edgeData.label === 'EXPOSES') {
                        const srvData = this.nodeIndex.get(edgeData.target);
                        if (srvData && ['service', 'http', 'https'].includes(srvData.type)) {
                            services.push(srvData);
                        }
                    }
                });
            });
            
            if (selfData && selfData.passive_services && Array.isArray(selfData.passive_services)) {
                selfData.passive_services.forEach(srv => services.push(srv));
            }
            
            // Remove duplicates
            const uniqueServices = services.filter((service, index, self) => 
                index === self.findIndex(s => s.id === service.id)
            );
            
            return uniqueServices;
        } catch (error) {
            console.error('Error in findConnectedServices:', error);
            return [];
        }
    }
    
    findConnectedSubdomains(nodeId, elements) {
        if (!elements || !elements.edges) return [];
        if (!this.nodeIndex) this.buildGraphIndex(elements);

        const targetData = this.nodeIndex.get(nodeId);
        if (!targetData) return [];

        const subdomainsMap = new Map();
        const visitedSubIds = new Set();
        const visitedDomIds = new Set();

        if (targetData.type === 'target') {
            const nodeOut = this.outEdges.get(nodeId) || [];
            nodeOut.forEach(edgeData => {
                if (edgeData.label === 'MATCHES_DOMAIN') {
                    visitedDomIds.add(edgeData.target);
                }
            });
        }

        if (targetData.type === 'domain') {
            visitedDomIds.add(nodeId);
        }

        visitedDomIds.forEach(domId => {
            const domOut = this.outEdges.get(domId) || [];
            domOut.forEach(edgeData => {
                if (edgeData.label === 'HAS_SUBDOMAIN' || edgeData.label === 'CONTAINS_SUBDOMAIN') {
                    visitedSubIds.add(edgeData.target);
                }
            });
        });

        // Recursively traverse downstream subdomains
        const visitedNodes = new Set();
        const processSubTree = (subId, isRootNode = false) => {
            if (visitedNodes.has(subId)) return;
            visitedNodes.add(subId);

            if (!isRootNode) {
                const sData = this.nodeIndex.get(subId);
                if (sData && sData.type === 'subdomain') {
                    subdomainsMap.set(sData.id, sData);
                }
            }

            const subOut = this.outEdges.get(subId) || [];
            subOut.forEach(edgeData => {
                if (edgeData.label === 'HAS_SUBDOMAIN' || edgeData.label === 'CONTAINS_SUBDOMAIN') {
                    processSubTree(edgeData.target, false);
                }
            });
        };

        if (targetData.type === 'subdomain') {
            processSubTree(nodeId, true);
        }

        visitedSubIds.forEach(subId => {
            processSubTree(subId, false);
        });

        return Array.from(subdomainsMap.values());
    }

    countConnectedIPs(domainId, elements) {
        return this.findConnectedIPs(domainId, elements).length;
    }

    renderLeadSelector() {
        console.log('=== RENDER LEAD SELECTOR START ===');
        const leadList = document.getElementById('lead-list');
        if (!leadList) {
            console.error('❌ Lead list element not found in renderLeadSelector');
            return;
        }

        console.log(`Rendering ${this.leads.length} leads`);

        if (this.leads.length === 0) {
            console.error('❌ CRITICAL: Still no leads to render after all fallbacks!');
            leadList.innerHTML = `
                <div class="lead-loading" style="color: #ff4757;">
                    ❌ No leads found in database<br>
                    <small>All fallback methods failed</small><br>
                    <button onclick="console.log('Graph data:', window.dashboard.graphData); window.dashboard.populateLeadSelector(window.dashboard.graphData?.elements)" 
                            style="margin-top: 10px; padding: 5px 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer;">
                        Debug & Retry
                    </button><br>
                    <button onclick="location.reload()" 
                            style="margin-top: 5px; padding: 5px 10px; background: #dc3545; color: white; border: none; border-radius: 3px; cursor: pointer;">
                        Reload Page
                    </button>
                </div>
            `;
            return;
        }

        console.log('✓ Clearing lead list and rendering leads...');
        leadList.innerHTML = '';
        const fragment = document.createDocumentFragment();

        // Sort leads strictly following the 3D Risk Matrix criteria:
        // Dim 3 (Active Threat / Weaponization) > Dim 2 (Technical Severity) > Dim 1 (Active Asset Exposure)
        const sortedLeads = [...this.leads].sort((a, b) => {
            if (b.three_d_score !== a.three_d_score) {
                return b.three_d_score - a.three_d_score;
            }
            if (b.kev_count !== a.kev_count) return b.kev_count - a.kev_count;
            if (b.poc_count !== a.poc_count) return b.poc_count - a.poc_count;
            if (b.max_epss !== a.max_epss) return b.max_epss - a.max_epss;
            if (b.critical_count !== a.critical_count) return b.critical_count - a.critical_count;
            if (b.high_count !== a.high_count) return b.high_count - a.high_count;
            if (b.verified_service_count !== a.verified_service_count) return b.verified_service_count - a.verified_service_count;
            if (b.vuln_count !== a.vuln_count) return b.vuln_count - a.vuln_count;
            if (b.service_count !== a.service_count) return b.service_count - a.service_count;
            return (a.display_name || '').localeCompare(b.display_name || '');
        });

        sortedLeads.forEach(lead => {
            const leadItem = document.createElement('div');
            leadItem.className = 'lead-item';
            leadItem.dataset.leadId = lead.id;

            // Build priority badges with proper visual indicators
            const badges = [];
            
            // CISA KEV badge (highest priority - red with pulse)
            if (lead.has_kev) {
                badges.push('<span class="lead-badge kev" title="CISA Known Exploited Vulnerability"><i data-lucide="shield-alert" class="badge-icon"></i> KEV</span>');
            }
            
            // Critical vulnerabilities badge
            if (lead.has_critical) {
                badges.push('<span class="lead-badge critical" title="Critical Severity Vulnerabilities"><i data-lucide="alert-triangle" class="badge-icon"></i> CRIT</span>');
            }

            // High EPSS badge (>= 20% 3D Matrix threshold)
            if (lead.max_epss >= 0.20) {
                const epssPct = (lead.max_epss * 100).toFixed(0);
                badges.push(`<span class="lead-badge epss" style="background: rgba(245, 158, 11, 0.18); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); font-size: 0.72rem; padding: 1px 5px; border-radius: 4px; font-weight: bold;" title="Max EPSS Probability: ${(lead.max_epss * 100).toFixed(1)}%"><i data-lucide="trending-up" class="badge-icon"></i> ${epssPct}% EPSS</span>`);
            }
            
            // PoC/Exploit availability badge
            if (lead.poc_count > 0) {
                badges.push(`<span class="lead-badge poc" title="${lead.poc_count} Proof-of-Concept(s) Available"><i data-lucide="file-code" class="badge-icon"></i> ${lead.poc_count} PoC</span>`);
            }
            
            // CVE count badge
            if (lead.vuln_count > 0) {
                badges.push(`<span class="lead-badge cve" title="${lead.vuln_count} CVE(s) Found"><i data-lucide="bug" class="badge-icon"></i> ${lead.vuln_count} CVE</span>`);
            }

            // Build detailed stats
            let stats = '';
            const verifiedText = lead.verified_service_count > 0 ? ` (${lead.verified_service_count} verified)` : '';
            if (lead.type === 'ip') {
                const orgInfo = lead.org && lead.org !== 'Unknown' ? ` (${lead.org})` : '';
                const countryInfo = lead.country && lead.country !== 'Unknown' ? ` [${lead.country}]` : '';
                stats = `${lead.service_count} services${verifiedText}, ${lead.vuln_count} vulns${orgInfo}${countryInfo}`;
            } else if (lead.type === 'domain') {
                stats = `${lead.ip_count} IPs, ${lead.service_count} services${verifiedText}, ${lead.vuln_count} vulns`;
            }

            // Add risk level indicator
            let riskClass = '';
            if (lead.has_kev) {
                riskClass = 'risk-critical';
            } else if (lead.has_critical || lead.poc_count > 0 || lead.max_epss >= 0.20) {
                riskClass = 'risk-high';
            } else if (lead.vuln_count > 0 || lead.verified_service_count > 0) {
                riskClass = 'risk-medium';
            } else {
                riskClass = 'risk-low';
            }

            const isSelected = this.selectedLeads.has(lead.id);
            const iconName = isSelected ? 'check-circle' : 'crosshair';
            const iconColor = isSelected ? '#10b981' : '#64748b';
            
            leadItem.innerHTML = `
                <div class="lead-target-btn" style="cursor: pointer; margin-right: 10px; display: flex; align-items: center; justify-content: center; color: ${iconColor};">
                    <i data-lucide="${iconName}" style="width: 18px; height: 18px;"></i>
                </div>
                <div class="lead-info" style="flex: 1;">
                    <div class="lead-header">
                        <span class="lead-name" style="cursor: pointer; font-weight: 500;">${lead.display_name}</span>
                        <div class="lead-type ${lead.type}">${lead.type.toUpperCase()}</div>
                    </div>
                    <div class="lead-badges">${badges.join('')}</div>
                    <div class="lead-stats">${stats}</div>
                </div>
                <div class="lead-risk-indicator ${riskClass}"></div>
            `;

            const toggleBtn = leadItem.querySelector('.lead-target-btn');
            
            const handleToggle = (e) => {
                e.stopPropagation();
                const currentlySelected = this.selectedLeads.has(lead.id);
                const willBeSelected = !currentlySelected;
                
                // Optimistic UI update
                if (willBeSelected) {
                    leadItem.classList.add('selected');
                    toggleBtn.style.color = '#10b981';
                    toggleBtn.innerHTML = '<i data-lucide="check-circle" style="width: 18px; height: 18px;"></i>';
                } else {
                    leadItem.classList.remove('selected');
                    toggleBtn.style.color = '#64748b';
                    toggleBtn.innerHTML = '<i data-lucide="crosshair" style="width: 18px; height: 18px;"></i>';
                }
                if (typeof lucide !== 'undefined') lucide.createIcons({ root: toggleBtn });
                
                window.toggleLeadVisibility(lead.id, willBeSelected);
            };

            toggleBtn.addEventListener('click', handleToggle);
            leadItem.addEventListener('click', (e) => {
                // Ignore clicks on buttons/links inside the item (if any are added later)
                if (e.target.closest('a') || e.target.closest('button')) return;
                handleToggle(e);
            });

            // Set initial state
            if (this.selectedLeads.has(lead.id)) {
                leadItem.classList.add('selected');
            }

            fragment.appendChild(leadItem);
        });

        leadList.appendChild(fragment);

        // Initialize Lucide icons inside dynamically rendered leads
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
        
        console.log(`✓ Rendered ${this.leads.length} lead items successfully`);
        console.log('=== RENDER LEAD SELECTOR END ===');
    }

    toggleLead(leadId) {
        const leadItem = document.querySelector(`[data-lead-id="${leadId}"]`);
        if (!leadItem) return;

        if (this.selectedLeads.has(leadId)) {
            this.selectedLeads.delete(leadId);
            leadItem.classList.remove('selected');
        } else {
            this.selectedLeads.add(leadId);
            leadItem.classList.add('selected');
        }

        this.applyLeadFilter({ relayout: true });
    }

    async selectAllLeads() {
        const ids = [];
        this.leads.forEach(lead => {
            if (!this.selectedLeads.has(lead.id)) {
                this.selectedLeads.add(lead.id);
                ids.push(lead.id);
            }
        });
        await this.setTargetsBulk(ids);
        this.renderLeadSelector(); // Re-render to update icons
        this.applyLeadFilter({ relayout: true });
    }

    async deselectAllLeads() {
        const ids = Array.from(this.selectedLeads);
        this.selectedLeads.clear();
        await this.removeTargetsBulk(ids);
        this.renderLeadSelector();
        this.applyLeadFilter({ relayout: true });
    }
    filterExploreLeads(query) {
        const q = String(query || '').trim().toLowerCase();
        const leadList = document.getElementById('lead-list');
        if (!leadList) return;
        
        const items = leadList.querySelectorAll('.lead-item');
        items.forEach(item => {
            const textContent = item.textContent || item.innerText || '';
            if (!q || textContent.toLowerCase().includes(q)) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    }

    applyLeadFilter(options = {}) {
        if (!this.cy) return;

        // Get selected lead IDs
        const selectedLeadIds = Array.from(this.selectedLeads);
        const visibleNodes = new Set();

        // Rule: When NO leads are selected (default upon DB load), render NOTHING except target_root!
        if (selectedLeadIds.length === 0) {
            this.cy.nodes().hide();
            this.cy.edges().hide();
            const rootNode = this.cy.getElementById('target_root');
            if (rootNode.length > 0) {
                rootNode.show();
                // Always gently center the root node when it becomes the only survivor
                this.cy.animate({
                    center: { eles: rootNode },
                    zoom: 1.2
                }, { duration: 500 });
            }
            this.visibleLeadNodes = new Set(['target_root']);
            return;
        }

        // Show all nodes and edges for filtering pass
        this.cy.nodes().show();
        this.cy.edges().show();

        // First pass: Find all selected lead nodes
        selectedLeadIds.forEach(leadId => {
            const node = this.cy.getElementById(leadId);
            if (node.length > 0) {
                visibleNodes.add(leadId);
            }
        });

        // Second pass: For each selected lead, add ancestry towards root and downstream descendants
        const addAncestors = (nodeId, visited = new Set()) => {
            if (visited.has(nodeId)) return;
            visited.add(nodeId);
            
            const node = this.cy.getElementById(nodeId);
            if (!node.length) return;
            
            node.incomers('node').forEach(parentNode => {
                const parentId = parentNode.id();
                visibleNodes.add(parentId);
                addAncestors(parentId, visited);
            });

            if (node.data('type') === 'ip') {
                node.outgoers('node[type="network"]').forEach(netNode => {
                    const netId = netNode.id();
                    visibleNodes.add(netId);
                    addAncestors(netId, visited);
                });
            }

            if (node.data('type') === 'domain' || node.data('type') === 'subdomain') {
                node.outgoers('node[type="ip"]').forEach(ipNode => {
                    ipNode.outgoers('node[type="network"]').forEach(netNode => {
                        const netId = netNode.id();
                        visibleNodes.add(netId);
                        addAncestors(netId, visited);
                    });
                });
            }
        };

        const addDescendants = (nodeId, visited = new Set()) => {
            if (visited.has(nodeId)) return;
            visited.add(nodeId);
            
            const node = this.cy.getElementById(nodeId);
            if (!node.length) return;
            
            node.outgoers('node').forEach(childNode => {
                const childId = childNode.id();
                visibleNodes.add(childId);
                addDescendants(childId, visited);
            });
        };

        selectedLeadIds.forEach(leadId => {
            addAncestors(leadId);
            addDescendants(leadId);
        });

        // Always ensure target_root is visible if any lead is selected
        const rootNode = this.cy.getElementById('target_root');
        if (rootNode.length > 0) {
            visibleNodes.add('target_root');
        }

        // Third pass: Smart Clustering / Collapsing for high fan-out nodes (>15 services or vulns)
        // Group overwhelming numbers of services or vulnerabilities into clean cluster nodes
        // Clustered counts and children adhere strictly to active vulnerability, category and search filters!
        const clusterNodesToAdd = [];
        const clusterEdgesToAdd = [];
        const CLUSTER_THRESHOLD = 15;

        // Vulnerability filter evaluator helper for clustering pass
        const hasVulnFilters = this.filters.matrix3d || this.filters.kev || this.filters.highEpss || this.filters.critical || this.filters.hideLowInfo || this.filters.nucleiOnly || this.filters.withPocs;
        const vulnMatchesActiveFilter = (vulnNode, parentContext = null) => {
            if (!vulnNode) return false;
            const data = typeof vulnNode.data === 'function' ? vulnNode.data() : vulnNode;
            const severity = String(data.severity || '').toUpperCase();
            const source = String(data.source || '').toLowerCase();
            
            if (this.filters.matrix3d) {
                // Dimensão 1: Exposição e Validação Ativa (O Ativo)
                let hasDirectActiveService = false;
                
                if (parentContext && ['service', 'http', 'https'].includes(parentContext.data('type'))) {
                    const sData = parentContext.data();
                    if (sData.verified_active === true || sData.is_active_scan === true) {
                        hasDirectActiveService = true;
                    } else {
                        const sSources = Array.isArray(sData.sources) ? sData.sources : (sData.sources ? [sData.sources] : []);
                        hasDirectActiveService = sSources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active')));
                    }
                } else if (typeof vulnNode.incomers === 'function') {
                    const parentServices = vulnNode.incomers('node[type="service"], node[type="http"], node[type="https"]');
                    if (parentServices.length > 0) {
                        hasDirectActiveService = parentServices.some(srv => {
                            const sData = srv.data();
                            if (sData.verified_active === true || sData.is_active_scan === true) return true;
                            const sSources = Array.isArray(sData.sources) ? sData.sources : (sData.sources ? [sData.sources] : []);
                            return sSources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active')));
                        });
                    }
                } else if (data.service_id && this.cy) {
                    const srv = this.cy.getElementById(data.service_id);
                    if (srv.length > 0) {
                        const sData = srv.data();
                        hasDirectActiveService = sData.verified_active === true || sData.is_active_scan === true;
                    }
                }

                // Sem serviço ativo diretamente associado -> desqualificado
                if (!hasDirectActiveService) return false;

                // Dimensão 2: Gravidade Técnica (O Impacto: elimina ruído Low/Info/Unknown)
                const cvss = parseFloat(data.cvss_score || 0);
                const hasTechImpact = severity === 'CRITICAL' || severity === 'HIGH' || (severity === 'MEDIUM' && cvss >= 5.0) || cvss >= 6.5;
                if (!hasTechImpact) return false;

                // Dimensão 3: Armamento no Mundo Real (A Ameaça Ativa: CISA KEV, Alto EPSS ou PoCs)
                const isKev = data.is_cisa_kev === true || data.is_cisa_kev === 'true' || data.is_cisa_kev === 1;
                const epss = parseFloat(data.epss_score || 0);
                const hasPocs = data.has_pocs === true || (Array.isArray(data.exploits) && data.exploits.length > 0) || (parseInt(data.exploit_count || 0) > 0);
                const realWorldThreat = isKev || (epss >= 0.2) || hasPocs;
                if (!realWorldThreat) return false;
            }

            if (this.filters.kev) {
                if (data.is_cisa_kev !== true && data.is_cisa_kev !== 1) return false;
            }
            if (this.filters.highEpss) {
                const epssScore = parseFloat(data.epss_score || 0);
                if (epssScore <= 0.5) return false;
            }
            if (this.filters.critical) {
                if (severity !== 'CRITICAL') return false;
            }
            if (this.filters.hideLowInfo) {
                if (severity === 'LOW' || severity === 'INFO' || severity === 'UNKNOWN') return false;
            }
            if (this.filters.nucleiOnly) {
                if (!source.includes('nuclei')) return false;
            }
            if (this.filters.withPocs) {
                const hasPocs = data.has_pocs === true || (Array.isArray(data.exploits) && data.exploits.length > 0);
                if (!hasPocs) return false;
            }
            return true;
        };

        // 3a. Cluster services under IP nodes with high fan-out or manual collapse
        this.cy.nodes('[type="ip"]').forEach(ipNode => {
            const clusterId = `cluster_srv_${ipNode.id()}`;
            const existingCluster = this.cy.getElementById(clusterId);

            if (!visibleNodes.has(ipNode.id())) {
                if (existingCluster.length > 0) existingCluster.remove();
                return;
            }

            let serviceOutgoers = ipNode.outgoers('node[type="service"], node[type="http"], node[type="https"]').filter(s => visibleNodes.has(s.id()) || s.id().startsWith('srv_'));
            
            // If vuln/category filters are active, only consider services that match or have matching vulns
            if (this.filters.vulnServicesOnly || hasVulnFilters) {
                serviceOutgoers = serviceOutgoers.filter(srv => {
                    const childVulns = srv.outgoers('node[type="vulnerability"]');
                    if (childVulns.length === 0) return false;
                    return hasVulnFilters ? childVulns.some(v => vulnMatchesActiveFilter(v, srv)) : true;
                });
            } else if (this.filters.verifiedServicesOnly) {
                serviceOutgoers = serviceOutgoers.filter(srv => {
                    const sData = typeof srv.data === 'function' ? srv.data() : srv;
                    if (sData.is_active_scan === true || sData.verified_active === true) return true;
                    const sources = Array.isArray(sData.sources) ? sData.sources : [];
                    return sources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active') || s.toLowerCase().includes('nuclei')));
                });
            }

            const isManuallyCollapsed = this.manualCollapsedClusters.has(clusterId);
            const isExpanded = this.expandedClusters.has(clusterId);
            const shouldCollapse = (isManuallyCollapsed || serviceOutgoers.length > CLUSTER_THRESHOLD) && !isExpanded;

            if (serviceOutgoers.length > 1 && shouldCollapse) {
                // Collapse services into a cluster node
                const clusterLabel = `+ ${serviceOutgoers.length} ${serviceOutgoers.length === 1 ? 'Service' : 'Services'}`;

                if (existingCluster.length === 0) {
                    const ipPos = ipNode.position();
                    // Offset services cluster to bottom-left of IP
                    clusterNodesToAdd.push({
                        group: 'nodes',
                        data: {
                            id: clusterId,
                            label: clusterLabel,
                            name: clusterLabel,
                            type: 'cluster_services',
                            parent_ip: ipNode.id(),
                            count: serviceOutgoers.length,
                            is_cluster: true
                        },
                        position: { x: ipPos.x - 42, y: ipPos.y + 45 }
                    });

                    clusterEdgesToAdd.push({
                        group: 'edges',
                        data: {
                            id: `edge_${clusterId}`,
                            source: ipNode.id(),
                            target: clusterId,
                            label: 'EXPOSES'
                        }
                    });
                } else {
                    existingCluster.data('label', clusterLabel);
                    existingCluster.data('count', serviceOutgoers.length);
                    const existingEdge = this.cy.getElementById(`edge_${clusterId}`);
                    if (existingEdge.length === 0) {
                        clusterEdgesToAdd.push({
                            group: 'edges',
                            data: {
                                id: `edge_${clusterId}`,
                                source: ipNode.id(),
                                target: clusterId,
                                label: 'EXPOSES'
                            }
                        });
                    }
                }

                visibleNodes.add(clusterId);

                // Hide individual service nodes and their downstream vulnerabilities
                serviceOutgoers.forEach(srvNode => {
                    visibleNodes.delete(srvNode.id());
                    srvNode.outgoers('node[type="vulnerability"]').forEach(vulnNode => {
                        visibleNodes.delete(vulnNode.id());
                    });
                });
            } else if (existingCluster.length > 0) {
                // Remove cluster if condition no longer met or expanded or single item
                existingCluster.remove();
            }
        });

        // 3b. Cluster direct vulnerabilities under IP nodes (IP -> Vulnerability without service)
        this.cy.nodes('[type="ip"]').forEach(ipNode => {
            const clusterId = `cluster_ip_vuln_${ipNode.id()}`;
            const existingCluster = this.cy.getElementById(clusterId);

            if (!visibleNodes.has(ipNode.id())) {
                if (existingCluster.length > 0) existingCluster.remove();
                return;
            }

            let directVulnOutgoers = ipNode.outgoers('node[type="vulnerability"]').filter(v => visibleNodes.has(v.id()) || v.id().startsWith('vuln_'));
            if (hasVulnFilters) {
                directVulnOutgoers = directVulnOutgoers.filter(v => vulnMatchesActiveFilter(v, ipNode));
            }

            const isManuallyCollapsed = this.manualCollapsedClusters.has(clusterId);
            const isExpanded = this.expandedClusters.has(clusterId);
            const shouldCollapse = (isManuallyCollapsed || directVulnOutgoers.length > CLUSTER_THRESHOLD) && !isExpanded;

            if (directVulnOutgoers.length > 1 && shouldCollapse) {
                const clusterLabel = `+ ${directVulnOutgoers.length} ${directVulnOutgoers.length === 1 ? 'Vuln' : 'Vulns'}`;

                if (existingCluster.length === 0) {
                    const ipPos = ipNode.position();
                    // Offset direct vulns cluster to bottom-right of IP
                    clusterNodesToAdd.push({
                        group: 'nodes',
                        data: {
                            id: clusterId,
                            label: clusterLabel,
                            name: clusterLabel,
                            type: 'cluster_vulns',
                            parent_ip: ipNode.id(),
                            count: directVulnOutgoers.length,
                            is_cluster: true
                        },
                        position: { x: ipPos.x + 42, y: ipPos.y + 45 }
                    });

                    clusterEdgesToAdd.push({
                        group: 'edges',
                        data: {
                            id: `edge_${clusterId}`,
                            source: ipNode.id(),
                            target: clusterId,
                            label: 'HAS_VULN'
                        }
                    });
                } else {
                    existingCluster.data('label', clusterLabel);
                    existingCluster.data('count', directVulnOutgoers.length);
                    const existingEdge = this.cy.getElementById(`edge_${clusterId}`);
                    if (existingEdge.length === 0) {
                        clusterEdgesToAdd.push({
                            group: 'edges',
                            data: {
                                id: `edge_${clusterId}`,
                                source: ipNode.id(),
                                target: clusterId,
                                label: 'HAS_VULN'
                            }
                        });
                    }
                }

                visibleNodes.add(clusterId);

                // Hide individual direct vulnerability nodes
                directVulnOutgoers.forEach(vulnNode => {
                    visibleNodes.delete(vulnNode.id());
                });
            } else if (existingCluster.length > 0) {
                existingCluster.remove();
            }
        });

        // 3c. Cluster vulnerabilities under Services with high fan-out or manual collapse
        this.cy.nodes('[type="service"], node[type="http"], node[type="https"]').forEach(srvNode => {
            const clusterId = `cluster_vuln_${srvNode.id()}`;
            const existingCluster = this.cy.getElementById(clusterId);

            // If the service is not visible, remove any orphaned vulnerability cluster
            if (!visibleNodes.has(srvNode.id())) {
                if (existingCluster.length > 0) existingCluster.remove();
                return;
            }

            let vulnOutgoers = srvNode.outgoers('node[type="vulnerability"]').filter(v => visibleNodes.has(v.id()) || v.id().startsWith('vuln_'));
            if (hasVulnFilters) {
                vulnOutgoers = vulnOutgoers.filter(v => vulnMatchesActiveFilter(v, srvNode));
            }

            const isManuallyCollapsed = this.manualCollapsedClusters.has(clusterId);
            const isExpanded = this.expandedClusters.has(clusterId);
            const shouldCollapse = (isManuallyCollapsed || vulnOutgoers.length > CLUSTER_THRESHOLD) && !isExpanded;

            if (vulnOutgoers.length > 1 && shouldCollapse) {
                const clusterLabel = `+ ${vulnOutgoers.length} ${vulnOutgoers.length === 1 ? 'Vuln' : 'Vulns'}`;

                if (existingCluster.length === 0) {
                    const srvPos = srvNode.position();
                    clusterNodesToAdd.push({
                        group: 'nodes',
                        data: {
                            id: clusterId,
                            label: clusterLabel,
                            name: clusterLabel,
                            type: 'cluster_vulns',
                            parent_srv: srvNode.id(),
                            count: vulnOutgoers.length,
                            is_cluster: true
                        },
                        position: { x: srvPos.x, y: srvPos.y + 45 }
                    });

                    clusterEdgesToAdd.push({
                        group: 'edges',
                        data: {
                            id: `edge_${clusterId}`,
                            source: srvNode.id(),
                            target: clusterId,
                            label: 'HAS_VULN'
                        }
                    });
                } else {
                    existingCluster.data('label', clusterLabel);
                    existingCluster.data('count', vulnOutgoers.length);
                    const existingEdge = this.cy.getElementById(`edge_${clusterId}`);
                    if (existingEdge.length === 0) {
                        clusterEdgesToAdd.push({
                            group: 'edges',
                            data: {
                                id: `edge_${clusterId}`,
                                source: srvNode.id(),
                                target: clusterId,
                                label: 'HAS_VULN'
                            }
                        });
                    }
                }

                visibleNodes.add(clusterId);

                // Hide individual vulnerability nodes
                vulnOutgoers.forEach(vulnNode => {
                    visibleNodes.delete(vulnNode.id());
                });
            } else if (existingCluster.length > 0) {
                existingCluster.remove();
            }
        });

        // Add dynamically created cluster elements to Cytoscape
        if (clusterNodesToAdd.length > 0) {
            this.cy.add(clusterNodesToAdd);
            this.cy.add(clusterEdgesToAdd);
            clusterNodesToAdd.forEach(c => visibleNodes.add(c.data.id));
        }

        // Store currently scoped visible lead nodes
        this.visibleLeadNodes = new Set(visibleNodes);

        // Fourth pass: Hide all nodes that are not in the visible set
        this.cy.nodes().forEach(node => {
            if (!visibleNodes.has(node.id())) {
                node.hide();
            } else {
                node.show();
            }
        });

        // Hide edges unless BOTH endpoints are visible
        this.cy.edges().forEach(edge => {
            const source = edge.source();
            const target = edge.target();
            if (source.hidden() || target.hidden() || !visibleNodes.has(source.id()) || !visibleNodes.has(target.id())) {
                edge.hide();
            } else {
                edge.show();
            }
        });

        // Apply other filters on top of lead filter
        this.applyFilters();

        // Check if this update was triggered by an Uncollapse / Expand action on a specific cluster
        if (options && options.expandedClusterId && options.parentId) {
            const parentNode = this.cy.getElementById(options.parentId);
            if (parentNode.length > 0) {
                const parentPos = parentNode.position();
                
                // Get the newly uncollapsed child nodes that remain visible after applyFilters()
                const isServiceCluster = options.expandedClusterId.startsWith('cluster_srv_');
                const childSelector = isServiceCluster ? 'node[type="service"], node[type="http"], node[type="https"]' : 'node[type="vulnerability"]';
                const children = parentNode.outgoers(childSelector).filter(c => !c.hidden());
                
                if (children.length > 0) {
                    const total = children.length;
                    const radius = Math.max(120, Math.min(260, 40 + total * 6));
                    
                    // Position parent's newly opened children in a neat organic fan-out without moving the rest of the graph
                    children.forEach((child, idx) => {
                        const angle = (idx / total) * 2 * Math.PI - (Math.PI / 2);
                        const targetX = parentPos.x + radius * Math.cos(angle);
                        const targetY = parentPos.y + radius * Math.sin(angle);
                        
                        child.show();
                        child.position({ x: parentPos.x, y: parentPos.y });
                        child.animate({
                            position: { x: targetX, y: targetY },
                            duration: 500,
                            easing: 'ease-out'
                        });
                    });

                    // Ensure connected edges to newly uncollapsed children are visible
                    this.cy.edges().forEach(edge => {
                        if (!edge.source().hidden() && !edge.target().hidden()) {
                            edge.show();
                        }
                    });
                    
                    // Smoothly adjust viewport to keep the expanded group nicely framed
                    setTimeout(() => {
                        if (this.cy) {
                            this.cy.animate({
                                fit: {
                                    eles: this.cy.elements(':visible'),
                                    padding: 50
                                },
                                duration: 400,
                                easing: 'ease-out'
                            });
                        }
                    }, 520);
                    return; // Done with localized expansion!
                }
            }
        }

        // Frame visible elements smoothly without recalculating layout positions (unless relayout was explicitly requested)
        if (visibleNodes.size > 0) {
            if (this._layoutDebounceTimer) {
                clearTimeout(this._layoutDebounceTimer);
            }
            this._layoutDebounceTimer = setTimeout(() => {
                if (!this.cy) return;
                this.cy.resize();
                const visibleElements = this.cy.elements(':visible');
                if (visibleElements.length === 0) return;
                
                // Determine if any visible node has zero or uninitialized position
                const hasUnpositionedNodes = visibleElements.nodes().some(n => {
                    const pos = n.position();
                    return !pos || (pos.x === 0 && pos.y === 0);
                });

                const shouldRelayout = options.relayout === true || !this._hasRunInitialLayout || hasUnpositionedNodes;
                if (shouldRelayout) {
                    this._hasRunInitialLayout = true;
                    const layoutSelect = document.getElementById('layout-select');
                    let layoutName = layoutSelect ? layoutSelect.value : this.getAvailableLayout();
                    if (layoutName === 'cose-bilkent' && typeof cytoscapeCoseBilkent === 'undefined') {
                        layoutName = 'cose';
                    }
                    const layoutOptions = this.getLayoutOptions(layoutName, visibleElements);

                    if (layoutOptions.name === 'preset' && layoutOptions.positions) {
                        const posMap = layoutOptions.positions;
                        const animDuration = 500;

                        visibleElements.nodes().forEach(node => {
                            const targetPos = posMap[node.id()];
                            if (targetPos) {
                                node.animate({
                                    position: targetPos,
                                    duration: animDuration,
                                    easing: 'ease-in-out'
                                });
                            }
                        });

                        setTimeout(() => {
                            if (this.cy) {
                                this.cy.resize();
                                const currentVisible = this.cy.nodes(':visible');
                                if (currentVisible.length > 0) {
                                    this.cy.animate({
                                        fit: {
                                            eles: currentVisible,
                                            padding: 50
                                        },
                                        duration: 350,
                                        easing: 'ease-out'
                                    });
                                }
                            }
                        }, animDuration + 20);
                    } else {
                        const layout = visibleElements.layout({
                            ...layoutOptions,
                            name: layoutOptions.name || layoutName,
                            animate: true,
                            animationDuration: 500,
                            animationEasing: 'ease-in-out',
                            stop: () => {
                                if (this.cy) {
                                    this.cy.resize();
                                    const currentVisible = this.cy.elements(':visible');
                                    if (currentVisible.length > 0) {
                                        this.cy.animate({
                                            fit: {
                                                eles: currentVisible,
                                                padding: 50
                                            },
                                            duration: 300,
                                            easing: 'ease-out'
                                        });
                                    }
                                }
                            }
                        });
                        layout.run();
                    }
                } else if (options.fitView !== false) {
                    // Frame the visible elements smoothly without moving any nodes
                    this.cy.resize();
                    this.cy.animate({
                        fit: {
                            eles: visibleElements,
                            padding: 50
                        },
                        duration: 300,
                        easing: 'ease-out'
                    });
                }
            }, 50);
        }
    }
    
    applyLeadVisibilityFilter(nodeId, isVisible) {
        // Delegate directly to applyLeadFilter which ensures exact consistency
        this.applyLeadFilter();
    }

    initCytoscape() {
        // Register the cose-bilkent layout extension if available
        if (typeof cytoscapeCoseBilkent !== 'undefined') {
            cytoscape.use(cytoscapeCoseBilkent);
        }
        
        this.cy = cytoscape({
            container: document.getElementById('cy'),
            
            style: [
                // Root / Primary Query Target nodes (Terminal App Squircle 1:1 Anchor)
                {
                    selector: 'node[type="target"], node[is_root="true"]',
                    style: {
                        'background-color': '#0D0E12',
                        'label': '',
                        'width': '64px',
                        'height': '64px',
                        'shape': 'round-rectangle',
                        'border-width': '0px',
                        'background-image': '/static/img/DetecTI_Security_Logo.png',
                        'background-fit': 'contain',
                        'background-width': '100%',
                        'background-height': '100%',
                        'background-position-x': '50%',
                        'background-position-y': '50%',
                        'background-opacity': 1
                    }
                },

                // Domain nodes
                {
                    selector: 'node[type="domain"]:not([is_root="true"])',
                    style: {
                        'background-color': '#00b4d8',
                        'label': 'data(label)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '12px',
                        'font-weight': 'bold',
                        'width': '65px',
                        'height': '65px',
                        'shape': 'ellipse',
                        'border-width': '2px',
                        'border-color': '#0096c7'
                    }
                },
                
                // Subdomain nodes
                {
                    selector: 'node[type="subdomain"]',
                    style: {
                        'background-color': '#4ecdc4',
                        'label': 'data(label)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '10px',
                        'width': '50px',
                        'height': '50px',
                        'shape': 'ellipse',
                        'border-width': '1px',
                        'border-color': '#3aa39c'
                    }
                },
                
                // IP address nodes
                {
                    selector: 'node[type="ip"]',
                    style: {
                        'background-color': '#9b59b6',
                        'label': function(ele) {
                            const ip = ele.data('ip') || ele.data('label') || '';
                            const fqdns = ele.data('fqdns') || [];
                            const fqdnCount = (ele.data('fqdn_count') !== undefined && ele.data('fqdn_count') !== null) ? ele.data('fqdn_count') : fqdns.length;
                            if (fqdnCount === 1) {
                                return `${ip}\n🌐 1 FQDN`;
                            } else if (fqdnCount > 1) {
                                return `${ip}\n🌐 ${fqdnCount} FQDNs`;
                            }
                            return ip;
                        },
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'text-wrap': 'wrap',
                        'text-max-width': '120px',
                        'line-height': 1.25,
                        'font-size': '9.5px',
                        'font-weight': 'bold',
                        'width': '100px',
                        'height': '48px',
                        'shape': 'round-rectangle',
                        'border-width': '2px',
                        'border-color': '#8e44ad'
                    }
                },
                
                // 1. Service nodes - Awaiting Active Confirmation (Passive candidate awaiting validation)
                {
                    selector: 'node[type="service"], node[type="http"], node[type="https"]',
                    style: {
                        'background-color': '#1e293b',
                        'label': 'data(label)',
                        'color': '#cbd5e1',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '9px',
                        'width': '44px',
                        'height': '44px',
                        'shape': 'hexagon',
                        'border-width': '1.5px',
                        'border-style': 'dashed',
                        'border-color': '#f59e0b',
                        'opacity': 0.85
                    }
                },
                
                // 2. Service nodes - Confirmed Active (Verified actively via Masscan / Active Scan) -> Emerald Green (#27ae60)
                {
                    selector: 'node[?verified_active], node[verified_active="true"], node[?is_active_scan], node[is_active_scan="true"]',
                    style: {
                        'background-color': '#27ae60',
                        'label': 'data(label)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '9px',
                        'font-weight': 'bold',
                        'width': '45px',
                        'height': '45px',
                        'shape': 'hexagon',
                        'border-style': 'solid',
                        'border-color': '#2ecc71',
                        'border-width': '2.5px',
                        'opacity': 1,
                        'box-shadow': '0 0 14px rgba(39, 174, 96, 0.65)'
                    }
                },

                // Target Node (Alvo Ativo: IP / FQDN) — Sinalização por Contorno Ciano Neon (#00f0ff)
                {
                    selector: 'node.is-target',
                    style: {
                        'border-color': '#00f0ff',
                        'border-width': '3px',
                        'border-style': 'solid'
                    }
                },

                // WAF Bypass Node (Origin IP Discovery)
                {
                    selector: 'node.is-waf-bypass',
                    style: {
                        'border-color': '#f97316',
                        'border-width': '4px',
                        'border-style': 'dashed'
                    }
                },
                
                // Vulnerability nodes
                {
                    selector: 'node[type="vulnerability"]',
                    style: {
                        'background-color': '#ef4444',
                        'label': 'data(cve_id)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '9px',
                        'font-weight': 'bold',
                        'width': '50px',
                        'height': '50px',
                        'shape': 'diamond',
                        'border-width': '2px',
                        'border-color': '#b91c1c'
                    }
                },
                
                // Critical severity vulnerabilities
                {
                    selector: 'node[type="vulnerability"][severity="CRITICAL"], node[risk_level="critical"]',
                    style: {
                        'background-color': '#ef4444',
                        'border-color': '#b91c1c',
                        'border-width': '3px'
                    }
                },

                // High severity vulnerabilities
                {
                    selector: 'node[type="vulnerability"][severity="HIGH"], node[risk_level="high"]',
                    style: {
                        'background-color': '#f97316',
                        'border-color': '#c2410c',
                        'border-width': '2px'
                    }
                },
                
                // Medium severity vulnerabilities
                {
                    selector: 'node[type="vulnerability"][severity="MEDIUM"], node[risk_level="medium"]',
                    style: {
                        'background-color': '#eab308',
                        'border-color': '#a16207',
                        'border-width': '2px'
                    }
                },
                
                // Low severity vulnerabilities
                {
                    selector: 'node[type="vulnerability"][severity="LOW"], node[risk_level="low"]',
                    style: {
                        'background-color': '#3b82f6',
                        'border-color': '#1d4ed8',
                        'border-width': '2px'
                    }
                },
                
                // Info severity vulnerabilities
                {
                    selector: 'node[type="vulnerability"][severity="INFO"], node[type="vulnerability"][severity="UNKNOWN"]',
                    style: {
                        'background-color': '#64748b',
                        'border-color': '#475569',
                        'border-width': '2px'
                    }
                },
                
                // CISA KEV vulnerabilities (special glow)
                {
                    selector: 'node[is_cisa_kev="true"]',
                    style: {
                        'background-color': '#ff1744',
                        'border-color': '#ffffff',
                        'border-width': '3px',
                        'box-shadow': '0 0 20px #ff1744'
                    }
                },
                
                // Edges
                {
                    selector: 'edge',
                    style: {
                        'width': '1.5px',
                        'line-color': '#555555',
                        'target-arrow-color': '#555555',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'straight',
                        'label': 'data(label)',
                        'font-size': '7px',
                        'color': '#ffffff',
                        'text-background-color': '#000000',
                        'text-background-opacity': 0.8,
                        'text-background-shape': 'roundrectangle',
                        'text-background-padding': '2px',
                        'text-rotation': 'autorotate'
                    }
                },
                
                // Vulnerability edges (HAS_VULN)
                {
                    selector: 'edge[label="HAS_VULN"]',
                    style: {
                        'line-color': '#ef4444',
                        'target-arrow-color': '#ef4444',
                        'width': '2px',
                        'line-style': 'dotted'
                    }
                },

                // Critical vulnerability edges
                {
                    selector: 'edge[label="HAS_VULN"][vuln_severity="CRITICAL"]',
                    style: {
                        'line-color': '#ef4444',
                        'target-arrow-color': '#ef4444',
                        'width': '2.5px',
                        'line-style': 'dotted'
                    }
                },

                // High vulnerability edges
                {
                    selector: 'edge[label="HAS_VULN"][vuln_severity="HIGH"]',
                    style: {
                        'line-color': '#f97316',
                        'target-arrow-color': '#f97316',
                        'width': '2px',
                        'line-style': 'dotted'
                    }
                },

                // Medium vulnerability edges
                {
                    selector: 'edge[label="HAS_VULN"][vuln_severity="MEDIUM"]',
                    style: {
                        'line-color': '#eab308',
                        'target-arrow-color': '#eab308',
                        'width': '2px',
                        'line-style': 'dotted'
                    }
                },

                // Low / Info vulnerability edges
                {
                    selector: 'edge[label="HAS_VULN"][vuln_severity="LOW"], edge[label="HAS_VULN"][vuln_severity="INFO"]',
                    style: {
                        'line-color': '#3b82f6',
                        'target-arrow-color': '#3b82f6',
                        'width': '1.5px',
                        'line-style': 'dotted'
                    }
                },
                
                // Service exposure edges (passive - dotted emerald green)
                {
                    selector: 'edge[label="EXPOSES"]',
                    style: {
                        'line-color': '#2ecc71',
                        'target-arrow-color': '#2ecc71',
                        'width': '2px',
                        'line-style': 'dotted'
                    }
                },
                
                // Relationship edges
                {
                    selector: 'edge[label="CONTAINS_TARGET"]',
                    style: {
                        'line-color': '#8c52ff',
                        'target-arrow-color': '#8c52ff',
                        'width': '2px'
                    }
                },


                {
                    selector: 'edge[label="RESOLVES_TO"]',
                    style: {
                        'line-color': '#4ecdc4',
                        'target-arrow-color': '#4ecdc4',
                        'width': '1.5px',
                        'opacity': 0.85
                    }
                },
                {
                    selector: 'edge[label="IPS_HISTORY"]',
                    style: {
                        'line-color': '#f59e0b',
                        'target-arrow-color': '#f59e0b',
                        'line-style': 'dashed',
                        'label': 'HISTORICAL_IP',
                        'width': '1.5px',
                        'opacity': 0.85
                    }
                },

                // Confirmed Active Service Edges (Solid emerald green line connecting IP -> Confirmed Active Service)
                {
                    selector: 'edge[?is_active_scan], edge[is_active_scan="true"], edge[?verified_active], edge[verified_active="true"], edge.active-scan-edge',
                    style: {
                        'line-style': 'solid',
                        'line-color': '#2ecc71',
                        'target-arrow-color': '#2ecc71',
                        'width': '2px'
                    }
                },
                
                // Cluster Nodes (Collapsible group for high fan-out services and vulnerabilities)
                {
                    selector: 'node[type="cluster_services"]',
                    style: {
                        'background-color': '#d35400',
                        'label': 'data(label)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '10px',
                        'font-weight': 'bold',
                        'width': '60px',
                        'height': '60px',
                        'shape': 'round-hexagon',
                        'border-width': '2.5px',
                        'border-color': '#ffffff',
                        'border-style': 'dashed',
                        'cursor': 'pointer'
                    }
                },
                {
                    selector: 'node[type="cluster_vulns"]',
                    style: {
                        'background-color': '#c0392b',
                        'label': 'data(label)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '10px',
                        'font-weight': 'bold',
                        'width': '60px',
                        'height': '60px',
                        'shape': 'round-diamond',
                        'border-width': '2.5px',
                        'border-color': '#ffffff',
                        'border-style': 'dashed',
                        'cursor': 'pointer'
                    }
                },
                
                // Selected nodes
                {
                    selector: 'node:selected, node.cy-selected',
                    style: {
                        'border-width': '3.5px',
                        'border-color': '#ffffff',
                        'box-shadow': '0 0 20px rgba(140, 82, 255, 0.9)'
                    }
                }
            ],
            
            boxSelectionEnabled: false,
            selectionType: 'additive',
            panningEnabled: true,
            userPanningEnabled: true,
            zoomingEnabled: true,
            userZoomingEnabled: true,
            minZoom: 0.05,
            maxZoom: 5.0,
            wheelSensitivity: 0.25,
            autoungrabify: false,
            autounselectify: false,
            
            layout: {
                name: 'preset'
            }
        });
    }

    async loadGraph(preserveLeadSelection = false) {
        try {
            console.log('Fetching graph data...');
            
            // Test API connection first
            await this.testAPIConnection();
            
            this.graphData = await window.api.getGraphData();
            console.log('Graph data received:', this.graphData);
            
            if (this.graphData && this.graphData.elements) {
                console.log(`Adding ${this.graphData.elements.nodes?.length || 0} nodes and ${this.graphData.elements.edges?.length || 0} edges`);
                
                // Debug: Log node types
                const nodeTypes = {};
                this.graphData.elements.nodes.forEach(node => {
                    const type = node.data.type;
                    nodeTypes[type] = (nodeTypes[type] || 0) + 1;
                });
                console.log('Node types in graph:', nodeTypes);
                
                this.cy.elements().remove();
                this.cy.add(this.graphData.elements);
                this._hasRunInitialLayout = false;
                
                // Build fast adjacency index in memory for O(1) lookups
                this.buildGraphIndex(this.graphData.elements);

                // Populate lead selector from graph data after elements are added
                console.log('Populating lead selector...');
                this.populateLeadSelector(this.graphData.elements, preserveLeadSelection);
                this.applyLeadFilter({ relayout: true });
                this.syncTargetNodesStyling();
                
                console.log('Graph rendered successfully');
            } else {
                console.warn('No graph elements received');
                this.showError('No graph data available');
            }
            
        } catch (error) {
            console.error('Failed to load graph data:', error);
            throw error; // Re-throw to be caught by init()
        }
    }

    async testAPIConnection() {
        try {
            console.log('Testing API connection...');
            const response = await fetch('/api/v1/summary');
            if (!response.ok) {
                throw new Error(`API returned ${response.status}: ${response.statusText}`);
            }
            const data = await response.json();
            console.log('✓ API connection successful:', data);
            return true;
        } catch (error) {
            console.error('❌ API connection failed:', error);
            throw new Error(`API connection failed: ${error.message}`);
        }
    }

    setupEventListeners() {
        // Track Ctrl/Cmd/Shift key state globally
        let isModifierHeld = false;
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Control' || e.key === 'Meta' || e.key === 'Shift' || e.ctrlKey || e.metaKey || e.shiftKey) {
                isModifierHeld = true;
            }
        });
        window.addEventListener('keyup', (e) => {
            if (!e.ctrlKey && !e.metaKey && !e.shiftKey) {
                isModifierHeld = false;
            }
        });

        // Node Left-Click Handler:
        // Single click: select ONLY this node and show inspector
        // Ctrl/Cmd + Left-Click: toggle selection on this node while keeping previously selected nodes
        this.cy.on('tap', 'node', (event) => {
            const node = event.target;
            const originalEvent = event.originalEvent;
            const isMultiSelect = isModifierHeld || (originalEvent && (originalEvent.ctrlKey || originalEvent.metaKey || originalEvent.shiftKey));

            this.hideContextMenu();

            if (isMultiSelect) {
                // Multi-select toggle
                if (node.hasClass('cy-selected') || node.selected()) {
                    node.removeClass('cy-selected').unselect();
                } else {
                    node.addClass('cy-selected').select();
                }
                // Ensure all selected nodes remain highlighted
                this.cy.nodes('.cy-selected').select();
            } else {
                // Single left click: select ONLY this node and show inspector
                this.cy.nodes().removeClass('cy-selected').unselect();
                this.cy.edges('edge[label="RESOLVES_TO"], edge[label="IPS_HISTORY"]').removeClass('ghost-active');
                node.addClass('cy-selected').select();
                const connectedGhost = node.connectedEdges('edge[label="RESOLVES_TO"], edge[label="IPS_HISTORY"]');
                connectedGhost.addClass('ghost-active');
                
                // Open inspector immediately
                this.showNodeInspector(node);
            }
        });

        // Core (Canvas) Right-Click Handler
        this.cy.on('cxttap', (event) => {
            if (event.target !== this.cy) return;
            const originalEvent = event.originalEvent;
            if (originalEvent) {
                originalEvent.preventDefault();
                originalEvent.stopPropagation();
            }

            const cyContainer = document.getElementById('cy');
            const containerRect = cyContainer ? cyContainer.getBoundingClientRect() : { left: 0, top: 0 };
            const renderedPos = event.renderedPosition;
            const clientX = containerRect.left + (renderedPos ? renderedPos.x : (originalEvent ? originalEvent.clientX : 100));
            const clientY = containerRect.top + (renderedPos ? renderedPos.y : (originalEvent ? originalEvent.clientY : 100));

            this.showCoreContextMenu(clientX, clientY);
        });

        // Node Right-Click Handler: Custom Context Menu
        this.cy.on('cxttap', 'node', (event) => {
            const node = event.target;
            const originalEvent = event.originalEvent;
            if (originalEvent) {
                originalEvent.preventDefault();
                originalEvent.stopPropagation();
            }

            // Select this node if not currently selected
            if (!node.selected() && !node.hasClass('cy-selected')) {
                this.cy.nodes().removeClass('cy-selected').unselect();
                node.addClass('cy-selected').select();
            }

            const cyContainer = document.getElementById('cy');
            const containerRect = cyContainer ? cyContainer.getBoundingClientRect() : { left: 0, top: 0 };
            const renderedPos = event.renderedPosition;
            const clientX = containerRect.left + (renderedPos ? renderedPos.x : (originalEvent ? originalEvent.clientX : 100));
            const clientY = containerRect.top + (renderedPos ? renderedPos.y : (originalEvent ? originalEvent.clientY : 100));

            this.showContextMenu(node, clientX, clientY);
        });

        // Ghost Edge Lighting Handlers:
        // Hovering or tapping a domain/subdomain/IP lights up its RESOLVES_TO edges
        this.cy.on('mouseover', 'node', (event) => {
            const node = event.target;
            const type = node.data('type');
            if (type === 'domain' || type === 'subdomain' || type === 'ip') {
                const connectedGhostEdges = node.connectedEdges('edge[label="RESOLVES_TO"], edge[label="IPS_HISTORY"]');
                connectedGhostEdges.addClass('ghost-active');
            }
        });

        this.cy.on('mouseout', 'node', (event) => {
            const node = event.target;
            // Only remove if not selected
            if (!node.selected() && !node.hasClass('cy-selected')) {
                this.cy.edges('edge[label="RESOLVES_TO"], edge[label="IPS_HISTORY"]').removeClass('ghost-active');
            }
        });

        // Background click handler (close inspector, context menu & unselect nodes)
        this.cy.on('tap', (event) => {
            this.hideContextMenu();
            
            // Close the floating leads modal if clicking anywhere on the graph
            const floatingModal = document.getElementById('floating-leads-modal');
            if (floatingModal) floatingModal.style.display = 'none';

            if (event.target === this.cy) {
                this.cy.edges('edge[label="RESOLVES_TO"], edge[label="IPS_HISTORY"]').removeClass('ghost-active');
                this.cy.nodes().removeClass('cy-selected').unselect();
                this.closeInspector();
            }
        });

        // Dismiss context menu on window click or Escape
        window.addEventListener('click', (e) => {
            const menu = document.getElementById('cy-context-menu');
            if (menu && !menu.contains(e.target)) {
                this.hideContextMenu();
            }
        });

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideContextMenu();
                this.closeInspector();
            }
        });

        // Window resize listener to keep Cytoscape graph perfectly sized
        let resizeTimer = null;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                if (this.cy) {
                    this.cy.resize();
                }
            }, 100);
        });

        // Responsive & Desktop Retractable Sidebar Toggle & Backdrop
        const sidebar = document.getElementById('dashboard-sidebar');
        const sidebarBackdrop = document.getElementById('sidebar-backdrop');
        const toggleSidebarBtn = document.getElementById('toggle-sidebar');
        const closeSidebarBtn = document.getElementById('close-sidebar');

        const isMobileScreen = () => window.innerWidth <= 992;

        const openSidebar = () => {
            if (!sidebar) return;
            if (isMobileScreen()) {
                sidebar.classList.add('open');
                if (sidebarBackdrop) sidebarBackdrop.classList.add('active');
            } else {
                sidebar.classList.remove('collapsed');
            }
            setTimeout(() => {
                if (this.cy) this.cy.resize();
            }, 320);
        };

        const closeSidebar = () => {
            if (!sidebar) return;
            if (isMobileScreen()) {
                sidebar.classList.remove('open');
                if (sidebarBackdrop) sidebarBackdrop.classList.remove('active');
            } else {
                sidebar.classList.add('collapsed');
            }
            setTimeout(() => {
                if (this.cy) this.cy.resize();
            }, 320);
        };

        const toggleSidebar = () => {
            if (!sidebar) return;
            if (isMobileScreen()) {
                if (sidebar.classList.contains('open')) {
                    closeSidebar();
                } else {
                    openSidebar();
                }
            } else {
                if (sidebar.classList.contains('collapsed')) {
                    openSidebar();
                } else {
                    closeSidebar();
                }
            }
        };

        if (toggleSidebarBtn) {
            toggleSidebarBtn.addEventListener('click', toggleSidebar);
        }

        if (closeSidebarBtn) {
            closeSidebarBtn.addEventListener('click', closeSidebar);
        }

        if (sidebarBackdrop) {
            sidebarBackdrop.addEventListener('click', closeSidebar);
        }

        // Mutually exclusive sidebar accordions: opening one collapses the others
        const sidebarAccordions = document.querySelectorAll('.sidebar .sidebar-accordion');
        sidebarAccordions.forEach(accordion => {
            accordion.addEventListener('toggle', () => {
                if (accordion.open) {
                    sidebarAccordions.forEach(other => {
                        if (other !== accordion && other.open) {
                            other.open = false;
                        }
                    });
                }
            });
        });

        // Inspector Backdrop
        const inspectorBackdrop = document.getElementById('inspector-backdrop');
        if (inspectorBackdrop) {
            inspectorBackdrop.addEventListener('click', () => {
                this.closeInspector();
            });
        }

        // Inverted Mouse Controls:
        // Left-Click: Pan the graph / click nodes
        // Right-Click Drag or Shift+Drag: Box-Selection of multiple nodes
        const cyContainer = document.getElementById('cy');
        const selectionHint = document.getElementById('spacebar-pan-hint');

        let isRightSelecting = false;
        let selectStartX = 0;
        let selectStartY = 0;
        let selectionBoxEl = null;

        // Helper to create visual selection rectangle for right-click drag
        const createSelectionBox = () => {
            let el = document.getElementById('custom-selection-box');
            if (!el) {
                el = document.createElement('div');
                el.id = 'custom-selection-box';
                el.className = 'custom-selection-box';
                if (cyContainer) {
                    cyContainer.appendChild(el);
                }
            }
            return el;
        };

        if (cyContainer) {
            // Disable default browser context menu on graph canvas
            cyContainer.addEventListener('contextmenu', (e) => {
                e.preventDefault();
            });

            // Native wheel zoom listener
            cyContainer.addEventListener('wheel', (e) => {
                if (!this.cy) return;
                e.preventDefault();
                
                const factor = e.deltaY < 0 ? 1.15 : 0.85;
                const rect = cyContainer.getBoundingClientRect();
                const pos = {
                    x: e.clientX - rect.left,
                    y: e.clientY - rect.top
                };
                
                const curZoom = this.cy.zoom();
                const newZoom = Math.min(Math.max(curZoom * factor, 0.1), 5.0);
                
                this.cy.zoom({
                    level: newZoom,
                    renderedPosition: pos
                });
            }, { passive: false });

            // Capture-phase mousedown: when Ctrl/Cmd is held, ensure shiftKey flag is set so Cytoscape's internal core doesn't clear selection
            cyContainer.addEventListener('mousedown', (e) => {
                if (e.button === 0 && (e.ctrlKey || e.metaKey || isModifierHeld)) {
                    try {
                        Object.defineProperty(e, 'shiftKey', { get: () => true, configurable: true });
                    } catch (_) {}
                }
            }, true);

            // Right-click mousedown to start box-selection
            cyContainer.addEventListener('mousedown', (e) => {
                if (e.button === 2) { // Right Click
                    e.preventDefault();
                    isRightSelecting = true;
                    const rect = cyContainer.getBoundingClientRect();
                    selectStartX = e.clientX - rect.left;
                    selectStartY = e.clientY - rect.top;

                    selectionBoxEl = createSelectionBox();
                    selectionBoxEl.style.left = `${selectStartX}px`;
                    selectionBoxEl.style.top = `${selectStartY}px`;
                    selectionBoxEl.style.width = '0px';
                    selectionBoxEl.style.height = '0px';
                    selectionBoxEl.style.display = 'block';

                    if (selectionHint) {
                        selectionHint.textContent = '⬚ Box Selection (Right-Click Drag) - Release to select nodes';
                        selectionHint.classList.add('visible');
                    }
                }
            });

            // Window mousemove to update right-click selection box
            window.addEventListener('mousemove', (e) => {
                if (isRightSelecting && selectionBoxEl && cyContainer) {
                    const rect = cyContainer.getBoundingClientRect();
                    const currentX = Math.max(0, Math.min(rect.width, e.clientX - rect.left));
                    const currentY = Math.max(0, Math.min(rect.height, e.clientY - rect.top));

                    const minX = Math.min(selectStartX, currentX);
                    const minY = Math.min(selectStartY, currentY);
                    const width = Math.abs(currentX - selectStartX);
                    const height = Math.abs(currentY - selectStartY);

                    selectionBoxEl.style.left = `${minX}px`;
                    selectionBoxEl.style.top = `${minY}px`;
                    selectionBoxEl.style.width = `${width}px`;
                    selectionBoxEl.style.height = `${height}px`;
                }
            });

            // Window mouseup to complete right-click box selection
            window.addEventListener('mouseup', (e) => {
                if (e.button === 2 && isRightSelecting) {
                    isRightSelecting = false;
                    
                    if (selectionBoxEl) {
                        selectionBoxEl.style.display = 'none';
                    }

                    if (selectionHint) {
                        selectionHint.classList.remove('visible');
                    }

                    if (this.cy && cyContainer) {
                        const rect = cyContainer.getBoundingClientRect();
                        const endX = Math.max(0, Math.min(rect.width, e.clientX - rect.left));
                        const endY = Math.max(0, Math.min(rect.height, e.clientY - rect.top));

                        const minX = Math.min(selectStartX, endX);
                        const maxX = Math.max(selectStartX, endX);
                        const minY = Math.min(selectStartY, endY);
                        const maxY = Math.max(selectStartY, endY);

                        // If user dragged more than threshold (5px), perform box selection
                        if (maxX - minX > 5 || maxY - minY > 5) {
                            // If Shift / Ctrl key not held, unselect previous nodes
                            if (!e.shiftKey && !e.ctrlKey && !e.metaKey && !isModifierHeld) {
                                this.cy.nodes().removeClass('cy-selected').unselect();
                            }

                            // Find and select all nodes within bounding box in rendered coordinates
                            this.cy.nodes().forEach(node => {
                                if (node.hidden()) return;
                                const renderedPos = node.renderedPosition();
                                if (
                                    renderedPos.x >= minX &&
                                    renderedPos.x <= maxX &&
                                    renderedPos.y >= minY &&
                                    renderedPos.y <= maxY
                                ) {
                                    node.addClass('cy-selected').select();
                                }
                            });
                        }
                    }
                }
            });

            // Global release handler on window to ensure no node stays stuck in grab state on pointer release
            window.addEventListener('mouseup', () => {
                if (this.cy) {
                    const grabbedNodes = this.cy.nodes(':grabbed');
                    if (grabbedNodes.length > 0) {
                        grabbedNodes.emit('free');
                    }
                }
            });
            window.addEventListener('pointerup', () => {
                if (this.cy) {
                    const grabbedNodes = this.cy.nodes(':grabbed');
                    if (grabbedNodes.length > 0) {
                        grabbedNodes.emit('free');
                    }
                }
            });
        }

        // Global Keydown listener for Escape and unselect
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeSidebar();
                this.closeInspector();
                if (this.cy) {
                    this.cy.nodes().removeClass('cy-selected').unselect();
                }
            }
        });

        // Floating quick action buttons
        const floatFitBtn = document.getElementById('btn-float-fit');
        if (floatFitBtn) {
            floatFitBtn.addEventListener('click', () => {
                if (this.cy) {
                    this.cy.resize();
                    this.cy.fit();
                }
            });
        }

        const floatResetBtn = document.getElementById('btn-float-reset');
        if (floatResetBtn) {
            floatResetBtn.addEventListener('click', () => {
                if (this.cy) {
                    this.cy.resize();
                    this.cy.zoom(1);
                    this.cy.center();
                }
            });
        }

        const floatRelayoutBtn = document.getElementById('btn-float-relayout');
        const layoutSelect = document.getElementById('layout-select');

        const runSmoothLayout = (layoutName) => {
            if (!this.cy) return;
            this.cy.resize();
            if (layoutName === 'cose-bilkent' && typeof cytoscapeCoseBilkent === 'undefined') {
                layoutName = 'cose';
            }
            const visibleNodes = this.cy.nodes(':visible');
            if (visibleNodes.length === 0) return;

            const target = this.cy.elements(':visible');
            const layoutOptions = this.getLayoutOptions(layoutName, target);

            if (layoutOptions.name === 'preset' && layoutOptions.positions) {
                const posMap = layoutOptions.positions;
                const animDuration = 600;

                // Animate all visible nodes directly to their calculated hierarchical positions
                visibleNodes.forEach(node => {
                    const targetPos = posMap[node.id()];
                    if (targetPos) {
                        node.animate({
                            position: targetPos,
                            duration: animDuration,
                            easing: 'ease-in-out'
                        });
                    }
                });

                // Auto-fit viewport smoothly to frame the entire graph cleanly
                setTimeout(() => {
                    if (this.cy) {
                        this.cy.resize();
                        const currentVisible = this.cy.nodes(':visible');
                        if (currentVisible.length > 0) {
                            this.cy.animate({
                                fit: {
                                    eles: currentVisible,
                                    padding: 50
                                },
                                duration: 400,
                                easing: 'ease-out'
                            });
                        }
                    }
                }, animDuration + 20);
            } else {
                // Physics-based layouts (cose, cose-bilkent, etc.)
                // Force randomize: false so it uses current positions and just smoothly applies gravity/repulsion
                const layout = target.layout({
                    ...layoutOptions,
                    name: layoutOptions.name || layoutName,
                    fit: true,
                    padding: 40,
                    randomize: false,
                    animate: true,
                    animationDuration: 1000,
                    animationEasing: 'ease-out-cubic'
                });

                layout.on('layoutstop', () => {
                    if (this.cy) {
                        this.cy.animate({
                            fit: {
                                eles: visibleNodes,
                                padding: 45
                            },
                            duration: 350,
                            easing: 'ease-out'
                        });
                    }
                });

                layout.run();
            }
        };

        if (floatRelayoutBtn) {
            floatRelayoutBtn.addEventListener('click', () => {
                let layoutName = layoutSelect ? layoutSelect.value : this.getAvailableLayout();
                runSmoothLayout(layoutName);
            });
        }

        if (layoutSelect) {
            layoutSelect.addEventListener('change', (e) => {
                // Collapse all expanded clusters back to their default compact grouped state
                this.expandedClusters.clear();
                let layoutName = e.target.value || this.getAvailableLayout();
                runSmoothLayout(layoutName);
            });
        }

        // Search functionality
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchTerm = e.target.value.toLowerCase().trim();
                this.applyFilters({ relayout: false });
            });
        }

        const clearSearchBtn = document.getElementById('clear-search');
        if (clearSearchBtn) {
            clearSearchBtn.addEventListener('click', () => {
                if (searchInput) searchInput.value = '';
                this.searchTerm = '';
                this.applyFilters({ relayout: false });
            });
        }

        // Lead selector controls (using global functions as specified in HTML)
        window.selectAllLeads = (selectAll) => {
            if (selectAll) {
                this.selectAllLeads();
            } else {
                this.deselectAllLeads();
            }
        };
        
        window.toggleLeadVisibility = async (nodeId, isChecked) => {
            const cleanId = nodeId.replace(/^(ip_|dom_|sub_)/, '');
            if (isChecked) {
                this.selectedLeads.add(nodeId);
                await this.setTarget(cleanId);
            } else {
                this.selectedLeads.delete(nodeId);
                await this.removeTarget(cleanId);
            }
            
            // UI is updated optimistically before this is called
            
            // Apply lead filter to show/hide entire subtrees and frame active leads
            this.applyLeadFilter({ relayout: true });
        };

        // Filter checkboxes
        const filter3dMatrix = document.getElementById('filter-3d-matrix');
        if (filter3dMatrix) {
            filter3dMatrix.addEventListener('change', (e) => {
                this.filters.matrix3d = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        const filterKev = document.getElementById('filter-kev');
        if (filterKev) {
            filterKev.addEventListener('change', (e) => {
                this.filters.kev = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        const filterHighEpss = document.getElementById('filter-high-epss');
        if (filterHighEpss) {
            filterHighEpss.addEventListener('change', (e) => {
                this.filters.highEpss = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        const filterCritical = document.getElementById('filter-critical');
        if (filterCritical) {
            filterCritical.addEventListener('change', (e) => {
                this.filters.critical = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        const filterHideLowInfo = document.getElementById('filter-hide-low-info');
        if (filterHideLowInfo) {
            filterHideLowInfo.addEventListener('change', (e) => {
                this.filters.hideLowInfo = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        const filterNucleiOnly = document.getElementById('filter-nuclei-only');
        if (filterNucleiOnly) {
            filterNucleiOnly.addEventListener('change', (e) => {
                this.filters.nucleiOnly = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        const filterWithPocs = document.getElementById('filter-with-pocs');
        if (filterWithPocs) {
            filterWithPocs.addEventListener('change', (e) => {
                this.filters.withPocs = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        const filterServicesOnly = document.getElementById('filter-services-only');
        if (filterServicesOnly) {
            filterServicesOnly.addEventListener('change', (e) => {
                this.filters.servicesOnly = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        const filterVerifiedServices = document.getElementById('filter-verified-services');
        if (filterVerifiedServices) {
            filterVerifiedServices.addEventListener('change', (e) => {
                this.filters.verifiedServicesOnly = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        const filterVulnServices = document.getElementById('filter-vuln-services');
        if (filterVulnServices) {
            filterVulnServices.addEventListener('change', (e) => {
                this.filters.vulnServicesOnly = e.target.checked;
                this.applyLeadFilter({ relayout: false });
            });
        }

        // Inspector close button
        const closeFloatingLeads = document.getElementById('close-floating-leads');
        if (closeFloatingLeads) {
            closeFloatingLeads.addEventListener('click', () => {
                document.getElementById('floating-leads-modal').style.display = 'none';
            });
        }

        const closeInspectorBtn = document.getElementById('close-inspector');
        if (closeInspectorBtn) {
            closeInspectorBtn.addEventListener('click', () => {
                this.closeInspector();
            });
        }

        // Database Selector Dropdown Controls
        const dbDropdownWrapper = document.getElementById('db-dropdown-wrapper');
        const btnDbDropdown = document.getElementById('btn-db-dropdown');

        if (btnDbDropdown && dbDropdownWrapper) {
            btnDbDropdown.addEventListener('click', (e) => {
                e.stopPropagation();
                dbDropdownWrapper.classList.toggle('active');
                const isExpanded = dbDropdownWrapper.classList.contains('active');
                btnDbDropdown.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
            });

            // Close dropdown when clicking outside
            document.addEventListener('click', (e) => {
                if (!dbDropdownWrapper.contains(e.target)) {
                    dbDropdownWrapper.classList.remove('active');
                    btnDbDropdown.setAttribute('aria-expanded', 'false');
                }
            });
        }

        // Delete Database Modal Controls
        const deleteDbModal = document.getElementById('delete-db-modal');
        const btnCloseDeleteDb = document.getElementById('btn-close-delete-db-modal');
        const btnCancelDeleteDb = document.getElementById('btn-cancel-delete-db');
        const btnConfirmDeleteDb = document.getElementById('btn-confirm-delete-db');

        if (btnCloseDeleteDb) {
            btnCloseDeleteDb.addEventListener('click', () => this.closeDeleteDbModal());
        }
        if (btnCancelDeleteDb) {
            btnCancelDeleteDb.addEventListener('click', () => this.closeDeleteDbModal());
        }
        if (btnConfirmDeleteDb) {
            btnConfirmDeleteDb.addEventListener('click', async () => await this.confirmDeleteDatabase());
        }
        if (deleteDbModal) {
            deleteDbModal.addEventListener('click', (e) => {
                if (e.target === deleteDbModal) {
                    this.closeDeleteDbModal();
                }
            });
        }

        // Export Dropdown Controls
        const exportDropdownWrapper = document.querySelector('.export-dropdown-wrapper');
        const btnExportDropdown = document.getElementById('btn-export-dropdown');
        const exportItemJson = document.getElementById('export-item-json');
        const exportItemMd = document.getElementById('export-item-md');
        const exportItemHtml = document.getElementById('export-item-html');
        const exportItemCsv = document.getElementById('export-item-csv');

        if (btnExportDropdown && exportDropdownWrapper) {
            btnExportDropdown.addEventListener('click', (e) => {
                e.stopPropagation();
                exportDropdownWrapper.classList.toggle('active');
                const isExpanded = exportDropdownWrapper.classList.contains('active');
                btnExportDropdown.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
            });

            // Close dropdown when clicking outside
            document.addEventListener('click', (e) => {
                if (!exportDropdownWrapper.contains(e.target)) {
                    exportDropdownWrapper.classList.remove('active');
                    btnExportDropdown.setAttribute('aria-expanded', 'false');
                }
            });
        }

        if (exportItemJson) {
            exportItemJson.addEventListener('click', () => {
                if (exportDropdownWrapper) exportDropdownWrapper.classList.remove('active');
                this.triggerExport('json');
            });
        }

        if (exportItemMd) {
            exportItemMd.addEventListener('click', () => {
                if (exportDropdownWrapper) exportDropdownWrapper.classList.remove('active');
                this.triggerExport('markdown');
            });
        }

        if (exportItemHtml) {
            exportItemHtml.addEventListener('click', () => {
                if (exportDropdownWrapper) exportDropdownWrapper.classList.remove('active');
                this.triggerExport('html');
            });
        }

        if (exportItemCsv) {
            exportItemCsv.addEventListener('click', () => {
                if (exportDropdownWrapper) exportDropdownWrapper.classList.remove('active');
                this.triggerExport('csv');
            });
        }
    }

    async loadDatabases() {
        try {
            console.log('Loading available databases list...');
            const listEl = document.getElementById('db-dropdown-list');
            const labelEl = document.getElementById('current-db-label');
            const countBadge = document.getElementById('db-count-badge');
            const dbInfoEl = document.getElementById('db-info');

            const data = await window.api.getDatabases();
            const databases = data.databases || [];

            if (countBadge) {
                countBadge.textContent = databases.length;
            }

            // Determine active target / database clean name without .sqlite
            let activeCleanName = 'No Database';
            if (data.current_target) {
                activeCleanName = String(data.current_target).replace(/\.sqlite$/i, '');
            } else if (data.current_db) {
                activeCleanName = String(data.current_db).replace(/\.sqlite$/i, '');
            }

            if (labelEl) {
                labelEl.textContent = activeCleanName;
                labelEl.title = `Current Database: ${activeCleanName}`;
            }

            if (dbInfoEl) {
                dbInfoEl.textContent = `DB: ${activeCleanName}`;
            }

            if (!listEl) return;
            listEl.innerHTML = '';

            if (databases.length === 0) {
                listEl.innerHTML = `
                    <div style="padding: 0.8rem; text-align: center; color: var(--text-muted); font-size: 0.78rem;">
                        No databases found in ~/.detecti/data/dbs/
                    </div>
                `;
                return;
            }

            databases.forEach(db => {
                const itemEl = document.createElement('div');
                itemEl.className = `db-dropdown-item ${db.is_current ? 'is-active' : ''}`;
                
                const dbFile = db.filename || (db.name && db.name.endsWith('.sqlite') ? db.name : `${db.name}.sqlite`);
                const cleanDisplayName = String(db.display_name || db.target || db.clean_name || db.name || '').replace(/\.sqlite$/i, '');
                const metaText = `${db.size_mb || 0} MB • ${db.modified || 'Recent'}`;

                itemEl.innerHTML = `
                    <button type="button" class="db-item-main" title="Switch to database: ${cleanDisplayName}">
                        <i data-lucide="database" class="db-item-icon"></i>
                        <div class="db-item-info">
                            <span class="db-item-name">${this.escapeHtml(cleanDisplayName)}</span>
                            <span class="db-item-meta">${this.escapeHtml(metaText)}</span>
                        </div>
                    </button>
                    <button type="button" class="btn-delete-db" title="Delete database ${cleanDisplayName}" aria-label="Delete database ${cleanDisplayName}">
                        <i data-lucide="trash-2" class="ui-icon" style="width: 14px; height: 14px;"></i>
                    </button>
                `;

                // Switch database on click
                const mainBtn = itemEl.querySelector('.db-item-main');
                if (mainBtn) {
                    mainBtn.addEventListener('click', async (e) => {
                        e.stopPropagation();
                        const dropdownWrapper = document.getElementById('db-dropdown-wrapper');
                        if (dropdownWrapper) dropdownWrapper.classList.remove('active');
                        await this.switchDatabase(dbFile);
                    });
                }

                // Open Delete Modal on click
                const deleteBtn = itemEl.querySelector('.btn-delete-db');
                if (deleteBtn) {
                    deleteBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        this.openDeleteDbModal(dbFile, cleanDisplayName);
                    });
                }

                listEl.appendChild(itemEl);
            });

            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }
        } catch (error) {
            console.error('Failed to load databases list:', error);
        }
    }

    showToast(type = 'info', message = '', duration = 4000) {
        try {
            let container = document.getElementById('toast-container');
            if (!container) {
                container = document.createElement('div');
                container.id = 'toast-container';
                container.className = 'toast-container';
                document.body.appendChild(container);
            }

            const toast = document.createElement('div');
            toast.className = `toast-notification toast-${type}`;
            
            let iconName = 'info';
            if (type === 'success') iconName = 'check-circle-2';
            else if (type === 'error') iconName = 'alert-octagon';
            else if (type === 'warning') iconName = 'alert-triangle';

            toast.innerHTML = `
                <i data-lucide="${iconName}" class="toast-icon"></i>
                <span class="toast-message">${this.escapeHtml(message)}</span>
                <button type="button" class="toast-close-btn" aria-label="Close notification">
                    <i data-lucide="x" class="ui-icon" style="width: 12px; height: 12px;"></i>
                </button>
            `;

            const closeBtn = toast.querySelector('.toast-close-btn');
            if (closeBtn) {
                closeBtn.addEventListener('click', () => {
                    toast.classList.add('fade-out');
                    setTimeout(() => toast.remove(), 250);
                });
            }

            container.appendChild(toast);
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }

            setTimeout(() => {
                if (toast.parentElement) {
                    toast.classList.add('fade-out');
                    setTimeout(() => toast.remove(), 250);
                }
            }, duration);
        } catch (e) {
            console.log(`[Toast ${type}]:`, message);
        }
    }

    openDeleteDbModal(filename, cleanName) {
        this.pendingDbDelete = { filename, cleanName };
        const modal = document.getElementById('delete-db-modal');
        const targetNameEl = document.getElementById('delete-db-target-name');
        if (targetNameEl) {
            targetNameEl.textContent = cleanName;
        }
        if (modal) {
            modal.style.display = 'flex';
        }
        // Close dropdown menu if open
        const dropdownWrapper = document.getElementById('db-dropdown-wrapper');
        if (dropdownWrapper) dropdownWrapper.classList.remove('active');
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }

    closeDeleteDbModal() {
        this.pendingDbDelete = null;
        const modal = document.getElementById('delete-db-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async confirmDeleteDatabase() {
        if (!this.pendingDbDelete) return;
        const { filename, cleanName } = this.pendingDbDelete;
        const confirmBtn = document.getElementById('btn-confirm-delete-db');

        try {
            if (confirmBtn) {
                confirmBtn.disabled = true;
                confirmBtn.innerHTML = '<span>Deleting...</span>';
            }

            const res = await window.api.deleteDatabase(filename);
            this.closeDeleteDbModal();

            if (res && res.success) {
                this.showToast('success', `Database '${cleanName}' deleted successfully.`);
                
                // Immediately refresh database selector list via AJAX
                await this.loadDatabases();

                if (res.was_current) {
                    if (res.new_active_db) {
                        await this.switchDatabase(res.new_active_db);
                    } else {
                        // No remaining databases
                        if (this.cy) {
                            this.cy.elements().remove();
                        }
                        await this.loadSummary();
                    }
                }
            } else {
                this.showToast('error', (res && (res.detail || res.error)) || `Failed to delete database '${cleanName}'.`);
                await this.loadDatabases();
            }
        } catch (error) {
            console.error('Error deleting database:', error);
            this.showToast('error', `Error deleting database: ${error.message}`);
            await this.loadDatabases();
        } finally {
            if (confirmBtn) {
                confirmBtn.disabled = false;
                confirmBtn.innerHTML = '<i data-lucide="trash-2" class="ui-icon" style="width: 14px; height: 14px;"></i><span>Delete Database</span>';
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }
        }
    }

    async switchDatabase(dbName) {
        try {
            const loadingEl = document.getElementById('graph-loading');
            if (loadingEl) {
                loadingEl.style.display = 'flex';
                const p = loadingEl.querySelector('p');
                if (p) p.textContent = `Switching database to ${dbName}...`;
            }

            // Reset current graph UI and filtering state
            this.selectedLeads.clear();
            this.expandedClusters.clear();
            this.manualCollapsedClusters.clear();
            this._hasRunInitialLayout = false;
            this.searchTerm = '';
            
            // Clear Target Management state
            this.markedTargets.clear();
            this.targetStatuses = {};
            this.renderTargetsList();
            
            const searchInput = document.getElementById('search-input');
            if (searchInput) searchInput.value = '';
            this.closeInspector();

            if (this.cy) {
                this.cy.elements().remove();
                this.cy.resize();
            }

            await window.api.selectDatabase(dbName);
            
            // Reload database info, metrics and graph
            await Promise.all([
                this.loadDatabases(),
                this.loadSummary()
            ]);
            await this.loadGraph();
            await this.syncTargetsFromBackend();

            if (loadingEl) {
                loadingEl.style.display = 'none';
            }
        } catch (error) {
            console.error('Failed to switch database:', error);
            this.showToast('error', `Error switching database: ${error.message}`);
            const loadingEl = document.getElementById('graph-loading');
            if (loadingEl) loadingEl.style.display = 'none';
            await this.loadDatabases();
        }
    }

    async syncTargetsFromBackend() {
        try {
            const status = await window.api.getScanStatus();
            if (status && Array.isArray(status.targets)) {
                let changed = false;
                status.targets.forEach(t => {
                    if (!this.markedTargets.has(t.ip)) {
                        this.markedTargets.add(t.ip);
                        changed = true;
                    }
                    this.targetStatuses[t.ip] = t;
                });
                
                this.updateTargetBadgeCount();
                this.renderTargetsList();
                
                if (this.cy) {
                    this.syncTargetNodesStyling();
                }

                if (changed && this.leads && this.leads.length > 0) {
                    this.leads.forEach(lead => {
                        if (this.isTargetMarked(lead.display_name || lead.label)) {
                            this.selectedLeads.add(lead.id);
                        }
                    });
                    this.applyLeadFilter({ relayout: true });
                }
            }
        } catch (e) {
            console.warn('Failed to sync targets from backend:', e);
        }
    }

    triggerExport(format = 'json') {
        const url = window.api.getExportUrl(format);
        // Create invisible anchor and trigger download
        const a = document.createElement('a');
        a.href = url;
        a.download = '';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }

    applyFilters() {
        if (!this.cy) return;

        if (this.selectedLeads.size === 0) {
            return; // Lead filter already hid everything
        }

        // Helper to trace full ancestor lineage up to target_root (Strict Attack Path: strictly upwards towards root)
        const addAllAncestors = (startNode, targetSet, visited = new Set()) => {
            if (!startNode || startNode.length === 0) return;
            const nodeId = startNode.id();
            if (visited.has(nodeId)) return;
            visited.add(nodeId);
            
            targetSet.add(nodeId);
            const nodeType = startNode.data('type');

            // 1. Vulnerability -> Service / IP
            if (nodeType === 'vulnerability' || nodeType === 'exploit') {
                startNode.incomers('node').forEach(parent => {
                    const pType = parent.data('type');
                    // When 3D Risk Matrix is active, only trace through verified active services
                    if (this.filters.matrix3d || this.filters.verifiedServicesOnly) {
                        if (['service', 'http', 'https'].includes(pType)) {
                            const sData = parent.data();
                            const isSrvActive = sData.verified_active === true || sData.is_active_scan === true ||
                                (Array.isArray(sData.sources) && sData.sources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active'))));
                            if (!isSrvActive) return;
                        }
                    }
                    if (!this.visibleLeadNodes || this.visibleLeadNodes.has(parent.id())) {
                        addAllAncestors(parent, targetSet, visited);
                    }
                });
                return;
            }

            // 2. Service -> IP
            if (['service', 'http', 'https', 'cluster_services'].includes(nodeType)) {
                startNode.incomers('node[type="ip"]').forEach(parentIp => {
                    if (!this.visibleLeadNodes || this.visibleLeadNodes.has(parentIp.id())) {
                        addAllAncestors(parentIp, targetSet, visited);
                    }
                });
                return;
            }

            // 3. IP -> Network (ASN) + Direct Resolving Subdomains -> Target Root
            if (nodeType === 'ip') {
                // IP -> Network (ASN) -> Target Root
                startNode.outgoers('node[type="network"]').forEach(netNode => {
                    const netId = netNode.id();
                    if (!this.visibleLeadNodes || this.visibleLeadNodes.has(netId)) {
                        addAllAncestors(netNode, targetSet, visited);
                    }
                });

                // IP -> Direct Incomer Subdomain / Domain -> Target Root
                startNode.incomers('node[type="subdomain"], node[type="domain"]').forEach(subNode => {
                    const subId = subNode.id();
                    if (!this.visibleLeadNodes || this.visibleLeadNodes.has(subId)) {
                        addAllAncestors(subNode, targetSet, visited);
                    }
                });

                // Direct link from Target Root
                startNode.incomers('node[type="target"]').forEach(targetNode => {
                    targetSet.add(targetNode.id());
                });
                return;
            }

            // 4. Subdomain -> Parent Domain / Subdomain -> Target Root
            if (nodeType === 'subdomain') {
                startNode.incomers('node[type="domain"], node[type="subdomain"], node[type="target"]').forEach(parent => {
                    const pId = parent.id();
                    if (!this.visibleLeadNodes || this.visibleLeadNodes.has(pId)) {
                        addAllAncestors(parent, targetSet, visited);
                    }
                });
                return;
            }

            // 5. Network / Domain -> Target Root
            if (nodeType === 'network' || nodeType === 'domain') {
                startNode.incomers('node[type="target"]').forEach(targetNode => {
                    targetSet.add(targetNode.id());
                });
                return;
            }

            // Fallback for any other node types
            startNode.incomers('node').forEach(parent => {
                const pId = parent.id();
                if (!this.visibleLeadNodes || this.visibleLeadNodes.has(pId)) {
                    addAllAncestors(parent, targetSet, visited);
                }
            });
        };

        // Helper to trace full descendant subtree downwards (children services, vulns, clusters)
        const addAllDescendants = (startNode, targetSet, visited = new Set()) => {
            if (!startNode || startNode.length === 0) return;
            const nodeId = startNode.id();
            if (visited.has(nodeId)) return;
            visited.add(nodeId);

            startNode.outgoers('node').forEach(child => {
                const cId = child.id();
                if ((!this.visibleLeadNodes || this.visibleLeadNodes.has(cId)) && nodesToKeep.has(cId)) {
                    targetSet.add(cId);
                    addAllDescendants(child, targetSet, visited);
                }
            });
        };

        // 1. Search filter matching IDs
        const searchMatchingNodeIds = new Set();
        if (this.searchTerm) {
            this.cy.nodes().forEach(node => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(node.id())) return;
                const data = node.data();
                let parentData = {};
                const parentNode = node.incomers('node').first();
                if (parentNode.length > 0) {
                    parentData = parentNode.data();
                } else if (data.is_cluster || data.type === 'cluster_services' || data.type === 'cluster_vulns') {
                    const parentId = data.parent_ip || data.parent_srv;
                    const pNode = this.cy.getElementById(parentId);
                    if (pNode.length > 0) parentData = pNode.data();
                }

                const isRoot = node.id() === 'target_root' || data.is_root === true;
                const fqdnsStr = (!isRoot && Array.isArray(data.fqdns)) ? data.fqdns.join(' ') : '';
                const targetsListStr = isRoot && Array.isArray(data.targets_list) ? data.targets_list.join(' ') : '';
                const parentFqdnsStr = (!isRoot && Array.isArray(parentData.fqdns)) ? parentData.fqdns.join(' ') : '';

                const searchableText = [
                    data.label,
                    data.name,
                    data.ip,
                    data.cve_id,
                    data.service,
                    data.product,
                    data.banner,
                    data.org,
                    data.country,
                    data.port ? data.port.toString() : '',
                    fqdnsStr,
                    targetsListStr,
                    parentData.label,
                    parentData.name,
                    parentData.ip,
                    parentData.org,
                    parentFqdnsStr
                ].filter(Boolean).join(' ').toLowerCase();
                
                if (searchableText.includes(this.searchTerm)) {
                    searchMatchingNodeIds.add(node.id());
                }
            });
        }

        // 2. Vulnerability filter evaluator
        const hasVulnFilters = this.filters.matrix3d || this.filters.kev || this.filters.highEpss || this.filters.critical || this.filters.hideLowInfo || this.filters.nucleiOnly || this.filters.withPocs;
        const vulnMatchesFilter = (vulnNode, parentContext = null) => {
            if (!vulnNode) return false;
            const data = typeof vulnNode.data === 'function' ? vulnNode.data() : vulnNode;
            const severity = String(data.severity || '').toUpperCase();
            const source = String(data.source || '').toLowerCase();

            if (this.filters.matrix3d) {
                // Dimensão 1: Exposição e Validação Ativa (O Ativo)
                let hasDirectActiveService = false;
                
                if (parentContext && ['service', 'http', 'https'].includes(parentContext.data('type'))) {
                    const sData = parentContext.data();
                    if (sData.verified_active === true || sData.is_active_scan === true) {
                        hasDirectActiveService = true;
                    } else {
                        const sSources = Array.isArray(sData.sources) ? sData.sources : (sData.sources ? [sData.sources] : []);
                        hasDirectActiveService = sSources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active')));
                    }
                } else if (typeof vulnNode.incomers === 'function') {
                    const parentServices = vulnNode.incomers('node[type="service"], node[type="http"], node[type="https"]');
                    if (parentServices.length > 0) {
                        hasDirectActiveService = parentServices.some(srv => {
                            const sData = srv.data();
                            if (sData.verified_active === true || sData.is_active_scan === true) return true;
                            const sSources = Array.isArray(sData.sources) ? sData.sources : (sData.sources ? [sData.sources] : []);
                            return sSources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active')));
                        });
                    }
                } else if (data.service_id && this.cy) {
                    const srv = this.cy.getElementById(data.service_id);
                    if (srv.length > 0) {
                        const sData = srv.data();
                        hasDirectActiveService = sData.verified_active === true || sData.is_active_scan === true;
                    }
                }

                // Sem serviço ativo diretamente associado -> desqualificado
                if (!hasDirectActiveService) return false;

                // Dimensão 2: Gravidade Técnica (O Impacto: elimina ruído Low/Info/Unknown)
                const cvss = parseFloat(data.cvss_score || 0);
                const hasTechImpact = severity === 'CRITICAL' || severity === 'HIGH' || (severity === 'MEDIUM' && cvss >= 5.0) || cvss >= 6.5;
                if (!hasTechImpact) return false;

                // Dimensão 3: Armamento no Mundo Real (A Ameaça Ativa: CISA KEV, Alto EPSS ou PoCs)
                const isKev = data.is_cisa_kev === true || data.is_cisa_kev === 'true' || data.is_cisa_kev === 1;
                const epss = parseFloat(data.epss_score || 0);
                const hasPocs = data.has_pocs === true || (Array.isArray(data.exploits) && data.exploits.length > 0) || (parseInt(data.exploit_count || 0) > 0);
                const realWorldThreat = isKev || (epss >= 0.2) || hasPocs;
                if (!realWorldThreat) return false;
            }

            if (this.filters.kev) {
                if (data.is_cisa_kev !== true && data.is_cisa_kev !== 1) return false;
            }
            if (this.filters.highEpss) {
                const epssScore = parseFloat(data.epss_score || 0);
                if (epssScore <= 0.5) return false;
            }
            if (this.filters.critical) {
                if (severity !== 'CRITICAL') return false;
            }
            if (this.filters.hideLowInfo) {
                if (severity === 'LOW' || severity === 'INFO' || severity === 'UNKNOWN') return false;
            }
            if (this.filters.nucleiOnly) {
                if (!source.includes('nuclei')) return false;
            }
            if (this.filters.withPocs) {
                const hasPocs = data.has_pocs === true || (Array.isArray(data.exploits) && data.exploits.length > 0);
                if (!hasPocs) return false;
            }
            return true;
        };

        // Determine which nodes and clusters should be kept
        const nodesToKeep = new Set();

        if (hasVulnFilters) {
                        // Find all matching vulnerabilities within lead scope
            this.cy.nodes('[type="vulnerability"]').forEach(node => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(node.id())) return;
                
                let matchesAnyContext = false;
                node.incomers('node').forEach(parent => {
                    if (vulnMatchesFilter(node, parent)) {
                        matchesAnyContext = true;
                        nodesToKeep.add(parent.id());
                        addAllAncestors(parent, nodesToKeep);
                    }
                });
                
                if (matchesAnyContext) {
                    nodesToKeep.add(node.id());
                } else if (vulnMatchesFilter(node)) {
                    // Fallback for isolated nodes
                    nodesToKeep.add(node.id());
                    addAllAncestors(node, nodesToKeep);
                }
            });

            // Evaluate cluster_vulns nodes
            this.cy.nodes('[type="cluster_vulns"]').forEach(cNode => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(cNode.id())) return;
                const parentId = cNode.data('parent_srv') || cNode.data('parent_ip');
                const parentNode = this.cy.getElementById(parentId);
                if (parentNode.length > 0) {
                    const childVulns = parentNode.outgoers('node[type="vulnerability"]');
                    const matching = childVulns.filter(v => vulnMatchesFilter(v, parentNode));
                    if (matching.length > 0) {
                        nodesToKeep.add(cNode.id());
                        nodesToKeep.add(parentId);
                        addAllAncestors(parentNode, nodesToKeep);
                        cNode.data('label', `+ ${matching.length} ${matching.length === 1 ? 'Vuln' : 'Vulns'}`);
                    }
                }
            });

            // Evaluate cluster_services nodes
            this.cy.nodes('[type="cluster_services"]').forEach(cNode => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(cNode.id())) return;
                const parentId = cNode.data('parent_ip');
                const parentNode = this.cy.getElementById(parentId);
                if (parentNode.length > 0) {
                    const srvNodes = parentNode.outgoers('node[type="service"], node[type="http"], node[type="https"]');
                    const matchingSrvs = srvNodes.filter(srv => srv.outgoers('node[type="vulnerability"]').some(v => vulnMatchesFilter(v, srv)));
                    const directVulns = parentNode.outgoers('node[type="vulnerability"]');
                    let hasMatch = directVulns.some(v => vulnMatchesFilter(v, parentNode)) || matchingSrvs.length > 0;
                    
                    if (matchingSrvs.length > 0) {
                        cNode.data('count', matchingSrvs.length);
                        cNode.data('label', `+ ${matchingSrvs.length} ${matchingSrvs.length === 1 ? 'Service' : 'Services'}`);
                    }

                    if (hasMatch) {
                        nodesToKeep.add(cNode.id());
                        nodesToKeep.add(parentId);
                        addAllAncestors(parentNode, nodesToKeep);
                    }
                }
            });
        } else if (this.filters.vulnServicesOnly) {
            this.cy.nodes('[type="vulnerability"]').forEach(node => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(node.id())) return;
                nodesToKeep.add(node.id());
                addAllAncestors(node, nodesToKeep);
            });
            this.cy.nodes('[type="cluster_vulns"]').forEach(cNode => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(cNode.id())) return;
                nodesToKeep.add(cNode.id());
                const parentId = cNode.data('parent_srv') || cNode.data('parent_ip');
                nodesToKeep.add(parentId);
                addAllAncestors(this.cy.getElementById(parentId), nodesToKeep);
            });
            this.cy.nodes('[type="cluster_services"]').forEach(cNode => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(cNode.id())) return;
                const parentId = cNode.data('parent_ip');
                const parentNode = this.cy.getElementById(parentId);
                if (parentNode.length > 0) {
                    const srvNodes = parentNode.outgoers('node[type="service"], node[type="http"], node[type="https"]');
                    const hasVuln = srvNodes.some(srv => srv.outgoers('node[type="vulnerability"]').length > 0) ||
                                    parentNode.outgoers('node[type="vulnerability"]').length > 0;
                    if (hasVuln) {
                        nodesToKeep.add(cNode.id());
                        nodesToKeep.add(parentId);
                        addAllAncestors(parentNode, nodesToKeep);
                    }
                }
            });
        } else if (this.filters.verifiedServicesOnly) {
            const isVerifiedActiveSrv = (srvNode) => {
                const data = typeof srvNode.data === 'function' ? srvNode.data() : srvNode;
                if (data.is_active_scan === true || data.verified_active === true) return true;
                const sources = Array.isArray(data.sources) ? data.sources : [];
                return sources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active') || s.toLowerCase().includes('nuclei')));
            };

            this.cy.nodes('[type="service"], node[type="http"], node[type="https"]').forEach(node => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(node.id())) return;
                if (isVerifiedActiveSrv(node)) {
                    nodesToKeep.add(node.id());
                    addAllAncestors(node, nodesToKeep);
                    node.outgoers('node').forEach(v => {
                        if (!this.visibleLeadNodes || this.visibleLeadNodes.has(v.id())) nodesToKeep.add(v.id());
                    });
                }
            });
            this.cy.nodes('[type="cluster_services"]').forEach(cNode => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(cNode.id())) return;
                const parentId = cNode.data('parent_ip');
                const parentNode = this.cy.getElementById(parentId);
                if (parentNode.length > 0) {
                    const srvNodes = parentNode.outgoers('node[type="service"], node[type="http"], node[type="https"]');
                    const activeSrvs = srvNodes.filter(isVerifiedActiveSrv);
                    if (activeSrvs.length > 0) {
                        nodesToKeep.add(cNode.id());
                        nodesToKeep.add(parentId);
                        addAllAncestors(parentNode, nodesToKeep);
                        cNode.data('count', activeSrvs.length);
                        cNode.data('label', `+ ${activeSrvs.length} Verified ${activeSrvs.length === 1 ? 'Service' : 'Services'}`);
                    }
                }
            });
        } else if (this.filters.servicesOnly) {
            this.cy.nodes('[type="service"], node[type="http"], node[type="https"]').forEach(node => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(node.id())) return;
                nodesToKeep.add(node.id());
                addAllAncestors(node, nodesToKeep);
                node.outgoers('node').forEach(v => {
                    if (!this.visibleLeadNodes || this.visibleLeadNodes.has(v.id())) nodesToKeep.add(v.id());
                });
            });
            this.cy.nodes('[type="cluster_services"]').forEach(cNode => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(cNode.id())) return;
                nodesToKeep.add(cNode.id());
                const parentId = cNode.data('parent_ip');
                nodesToKeep.add(parentId);
                addAllAncestors(this.cy.getElementById(parentId), nodesToKeep);
            });
        } else {
            // No restrictive category filter active: keep all nodes that are currently within the lead scope
            if (this.visibleLeadNodes && this.visibleLeadNodes.size > 0) {
                this.visibleLeadNodes.forEach(id => {
                    nodesToKeep.add(id);
                });
            } else {
                this.cy.nodes().forEach(node => {
                    nodesToKeep.add(node.id());
                });
            }
        }

        // Filter-Aware Cluster Retention:
        // Only keep collapsed cluster indicator nodes if their parent is kept AND (when filters are active)
        // the cluster actually contains matching items. If count drops to 0, hide the cluster.
        this.cy.nodes('[type="cluster_services"], [type="cluster_vulns"]').forEach(cNode => {
            const parentId = cNode.data('parent_ip') || cNode.data('parent_srv');
            if (!nodesToKeep.has(parentId)) {
                nodesToKeep.delete(cNode.id());
                return;
            }
            if (hasVulnFilters) {
                const parentNode = this.cy.getElementById(parentId);
                if (cNode.data('type') === 'cluster_vulns') {
                    const childVulns = parentNode.outgoers('node[type="vulnerability"]');
                    const matching = childVulns.filter(v => vulnMatchesFilter(v, parentNode));
                    if (matching.length === 0) {
                        nodesToKeep.delete(cNode.id());
                    } else {
                        nodesToKeep.add(cNode.id());
                        cNode.data('count', matching.length);
                        cNode.data('label', `+ ${matching.length} ${matching.length === 1 ? 'Vuln' : 'Vulns'}`);
                    }
                } else if (cNode.data('type') === 'cluster_services') {
                    const srvNodes = parentNode.outgoers('node[type="service"], node[type="http"], node[type="https"]');
                    const matchingSrvs = srvNodes.filter(srv => srv.outgoers('node[type="vulnerability"]').some(v => vulnMatchesFilter(v, srv)));
                    if (matchingSrvs.length === 0) {
                        nodesToKeep.delete(cNode.id());
                    } else {
                        nodesToKeep.add(cNode.id());
                        cNode.data('count', matchingSrvs.length);
                        cNode.data('label', `+ ${matchingSrvs.length} ${matchingSrvs.length === 1 ? 'Service' : 'Services'}`);
                    }
                }
            } else if (this.filters && this.filters.verifiedServicesOnly) {
                const parentNode = this.cy.getElementById(parentId);
                if (cNode.data('type') === 'cluster_services') {
                    const srvNodes = parentNode.outgoers('node[type="service"], node[type="http"], node[type="https"]');
                    const isVerifiedActiveSrv = (s) => {
                        const d = s.data();
                        return d.verified_active === true || d.is_active_scan === true;
                    };
                    const activeSrvs = srvNodes.filter(isVerifiedActiveSrv);
                    if (activeSrvs.length === 0) {
                        nodesToKeep.delete(cNode.id());
                    } else {
                        nodesToKeep.add(cNode.id());
                        cNode.data('count', activeSrvs.length);
                        cNode.data('label', `+ ${activeSrvs.length} Verified ${activeSrvs.length === 1 ? 'Service' : 'Services'}`);
                    }
                }
            } else if (!hasVulnFilters && !(this.filters && (this.filters.vulnServicesOnly || this.filters.verifiedServicesOnly || this.filters.servicesOnly))) {
                // No restrictive filter active: keep all cluster nodes for visible parents
                nodesToKeep.add(cNode.id());
            }
        });

        // Apply search filter intersection if search is active
        if (this.searchTerm) {
            const finalSearchKept = new Set();
            searchMatchingNodeIds.forEach(id => {
                const node = this.cy.getElementById(id);
                if (node.length > 0 && nodesToKeep.has(id)) {
                    finalSearchKept.add(id);
                    // Walk up to target_root
                    addAllAncestors(node, finalSearchKept);
                    // Walk down to child services, vulns, and clusters
                    addAllDescendants(node, finalSearchKept);
                }
            });
            this.cy.nodes('[type="cluster_services"], [type="cluster_vulns"]').forEach(cNode => {
                const parentId = cNode.data('parent_ip') || cNode.data('parent_srv');
                if (finalSearchKept.has(parentId)) {
                    finalSearchKept.add(cNode.id());
                }
            });
            nodesToKeep.clear();
            finalSearchKept.forEach(id => nodesToKeep.add(id));
        }

        // Always preserve target_root if it was visible in the Lead Filter
        const rootNode = this.cy.getElementById('target_root');
        if (rootNode.length > 0 && (!this.visibleLeadNodes || this.visibleLeadNodes.has('target_root'))) {
            nodesToKeep.add('target_root');
        }

        // Apply final visibility to all nodes
        this.cy.nodes().forEach(node => {
            const data = node.data();
            const nodeType = data.type;

            if (data.is_cluster || nodeType === 'cluster_services' || nodeType === 'cluster_vulns') {
                if (nodesToKeep.has(node.id())) {
                    node.show();
                } else {
                    node.hide();
                }
                return;
            }

            // Check if this node is collapsed into an active cluster
            if (['service', 'http', 'https'].includes(nodeType)) {
                const parentIp = node.incomers('node[type="ip"]').first();
                if (parentIp.length > 0) {
                    const srvCluster = this.cy.getElementById(`cluster_srv_${parentIp.id()}`);
                    if (srvCluster.length > 0 && nodesToKeep.has(srvCluster.id())) {
                        node.hide();
                        return;
                    }
                }
            }

            if (nodeType === 'vulnerability') {
                const parentNode = node.incomers('node').first();
                if (parentNode.length > 0) {
                    const vulnCluster = this.cy.getElementById(`cluster_vuln_${parentNode.id()}`);
                    const ipVulnCluster = this.cy.getElementById(`cluster_ip_vuln_${parentNode.id()}`);
                    const srvCluster = this.cy.getElementById(`cluster_srv_${parentNode.id()}`);
                    if ((vulnCluster.length > 0 && nodesToKeep.has(vulnCluster.id())) || 
                        (ipVulnCluster.length > 0 && nodesToKeep.has(ipVulnCluster.id())) || 
                        (srvCluster.length > 0 && nodesToKeep.has(srvCluster.id()))) {
                        node.hide();
                        return;
                    }
                }
            }

            // Standard node visibility
            if (nodesToKeep.has(node.id())) {
                node.show();
            } else {
                node.hide();
            }
        });

        // Hide edges connected to hidden nodes
        this.cy.edges().forEach(edge => {
            const source = edge.source();
            const target = edge.target();
            if (source.hidden() || target.hidden()) {
                edge.hide();
            } else {
                edge.show();
            }
        });

        // Anti-Orphan Integrity Pass:
        // Ensure no floating disconnected non-root node remains visible without its relationship edge
        this.cy.nodes().forEach(node => {
            if (node.hidden()) return;
            const data = node.data();
            if (data.is_root || data.type === 'target') return; // Root queries are the anchors

            const visibleInEdges = node.incomers('edge').filter(e => !e.hidden());
            const visibleOutEdges = node.outgoers('edge').filter(e => !e.hidden());

            // If a node is isolated without any visible edge connection, hide it
            if (visibleInEdges.length === 0 && visibleOutEdges.length === 0) {
                node.hide();
            }
        });
    }

    renderRiskMetricsAccordion(nodeData, elements) {
        const connectedVulns = this.findConnectedVulnerabilities(nodeData.id, elements);
        const connectedServices = (nodeData.type === 'ip' || nodeData.type === 'domain' || nodeData.type === 'subdomain' || nodeData.type === 'target' || nodeData.type === 'network') 
            ? this.findConnectedServices(nodeData.id, elements) 
            : [];
        
        const vulnsCount = connectedVulns.length;
        const criticalVulns = connectedVulns.filter(v => String(v.severity || '').toUpperCase() === 'CRITICAL');
        const criticalCount = criticalVulns.length;
        
        // Extract all exploits from connected vulnerabilities without duplicates
        const allExploits = [];
        const seenExploitKeys = new Set();
        connectedVulns.forEach(vuln => {
            const cveId = vuln.cve_id || vuln.label || vuln.name || 'Unknown CVE';
            if (vuln.exploits && Array.isArray(vuln.exploits) && vuln.exploits.length > 0) {
                vuln.exploits.forEach(exp => {
                    const expKey = `${cveId}_${exp.url || exp.title || exp.source}`;
                    if (!seenExploitKeys.has(expKey)) {
                        seenExploitKeys.add(expKey);
                        allExploits.push({
                            cve_id: cveId,
                            vuln_id: vuln.id,
                            title: exp.title || `Exploit for ${cveId}`,
                            source: exp.source || 'Exploit',
                            url: exp.url || '#',
                            verified: Boolean(exp.verified),
                            author: exp.author || '',
                            date: exp.date || '',
                            exploit_type: exp.exploit_type || ''
                        });
                    }
                });
            } else if ((vuln.exploit_count || 0) > 0) {
                const expKey = `${cveId}_poc_default`;
                if (!seenExploitKeys.has(expKey)) {
                    seenExploitKeys.add(expKey);
                    allExploits.push({
                        cve_id: cveId,
                        vuln_id: vuln.id,
                        title: `Exploit for ${cveId}`,
                        source: 'Public PoC',
                        url: '#',
                        verified: false,
                        author: '',
                        date: '',
                        exploit_type: 'PoC'
                    });
                }
            }
        });
        const pocCount = allExploits.length || connectedVulns.filter(v => (v.exploit_count || 0) > 0).length;

        // Render Vulnerabilities list HTML
        let vulnsListHtml = '';
        if (vulnsCount > 0) {
            vulnsListHtml = connectedVulns.map(v => {
                const sev = (v.severity || 'UNKNOWN').toUpperCase();
                const sevClass = (v.severity || 'unknown').toLowerCase();
                const isKev = v.is_cisa_kev === true || v.is_cisa_kev === 'true' || v.is_cisa_kev === 1;
                const cvss = v.cvss_score ? `CVSS ${v.cvss_score}` : '';
                const epss = v.epss_score ? `EPSS ${(v.epss_score * 100).toFixed(1)}%` : '';
                const expCount = (v.exploits && v.exploits.length) || v.exploit_count || 0;
                const cveName = v.cve_id || v.name || v.label;
                const vulnSource = v.source || 'NVD';
                const isNuclei = String(vulnSource).toLowerCase().includes('nuclei');
                const sourceBadge = isNuclei 
                    ? '<span class="mini-badge" style="background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4);"><i data-lucide="shield-alert" class="badge-icon"></i> Nuclei</span>'
                    : '<span class="mini-badge" style="background: rgba(0, 240, 255, 0.12); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.3);"><i data-lucide="database" class="badge-icon"></i> NVD</span>';
                
                return `
                <div class="risk-item-card vuln-item severity-${sevClass}">
                    <div class="risk-card-top">
                        <div class="risk-card-title">
                            <span class="cve-code">${cveName}</span>
                            ${sourceBadge}
                            ${isKev ? '<span class="mini-badge kev"><i data-lucide="shield-alert" class="badge-icon"></i> CISA KEV</span>' : ''}
                            ${expCount > 0 ? `<span class="mini-badge poc"><i data-lucide="file-code" class="badge-icon"></i> ${expCount} PoC</span>` : ''}
                        </div>
                        <span class="mini-badge severity ${sevClass}">${sev}</span>
                    </div>
                    <div class="risk-card-metrics">
                        ${cvss ? `<span class="metric-pill"><strong>Score:</strong> ${cvss}</span>` : ''}
                        ${epss ? `<span class="metric-pill"><strong>Prob:</strong> ${epss}</span>` : ''}
                        <span class="metric-pill" style="color: ${isNuclei ? '#c084fc' : '#00f0ff'};"><strong>Source:</strong> ${vulnSource}</span>
                    </div>
                    ${v.description ? `<div class="risk-card-desc" title="${String(v.description).replace(/"/g, '&quot;')}">${v.description}</div>` : ''}
                    <div class="risk-card-links">
                        ${cveName && cveName.startsWith('CVE-') ? `<a href="https://nvd.nist.gov/vuln/detail/${cveName}" target="_blank" rel="noopener" class="risk-link-btn"><i data-lucide="external-link" class="badge-icon"></i> NVD Details</a>` : ''}
                        ${v.id ? `<button type="button" class="risk-focus-btn" onclick="window.dashboard.focusNode('${v.id}')"><i data-lucide="focus" class="badge-icon"></i> Focus</button>` : ''}
                    </div>
                </div>`;
            }).join('');
        } else {
            vulnsListHtml = '<div class="risk-item-empty">No vulnerabilities detected for this asset.</div>';
        }

        // Render Critical Vulns list HTML
        let criticalListHtml = '';
        if (criticalCount > 0) {
            criticalListHtml = criticalVulns.map(v => {
                const isKev = v.is_cisa_kev === true || v.is_cisa_kev === 'true' || v.is_cisa_kev === 1;
                const cvss = v.cvss_score ? `CVSS ${v.cvss_score}` : '';
                const epss = v.epss_score ? `EPSS ${(v.epss_score * 100).toFixed(1)}%` : '';
                const expCount = (v.exploits && v.exploits.length) || v.exploit_count || 0;
                const cveName = v.cve_id || v.name || v.label;
                const vulnSource = v.source || 'NVD';
                const isNuclei = String(vulnSource).toLowerCase().includes('nuclei');
                const sourceBadge = isNuclei 
                    ? '<span class="mini-badge" style="background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4);"><i data-lucide="shield-alert" class="badge-icon"></i> Nuclei</span>'
                    : '<span class="mini-badge" style="background: rgba(0, 240, 255, 0.12); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.3);"><i data-lucide="database" class="badge-icon"></i> NVD</span>';
                
                return `
                <div class="risk-item-card vuln-item severity-critical">
                    <div class="risk-card-top">
                        <div class="risk-card-title">
                            <span class="cve-code" style="color: #ff4757;">${cveName}</span>
                            ${sourceBadge}
                            ${isKev ? '<span class="mini-badge kev"><i data-lucide="shield-alert" class="badge-icon"></i> CISA KEV</span>' : ''}
                            ${expCount > 0 ? `<span class="mini-badge poc"><i data-lucide="file-code" class="badge-icon"></i> ${expCount} PoC</span>` : ''}
                        </div>
                        <span class="mini-badge severity critical">CRITICAL</span>
                    </div>
                    <div class="risk-card-metrics">
                        ${cvss ? `<span class="metric-pill"><strong>Score:</strong> ${cvss}</span>` : ''}
                        ${epss ? `<span class="metric-pill"><strong>Prob:</strong> ${epss}</span>` : ''}
                        <span class="metric-pill" style="color: ${isNuclei ? '#c084fc' : '#00f0ff'};"><strong>Source:</strong> ${vulnSource}</span>
                    </div>
                    ${v.description ? `<div class="risk-card-desc" title="${String(v.description).replace(/"/g, '&quot;')}">${v.description}</div>` : ''}
                    <div class="risk-card-links">
                        <a href="https://nvd.nist.gov/vuln/detail/${cveName}" target="_blank" rel="noopener" class="risk-link-btn"><i data-lucide="external-link" class="badge-icon"></i> NVD Details</a>
                        ${v.id ? `<button type="button" class="risk-focus-btn" onclick="window.dashboard.focusNode('${v.id}')"><i data-lucide="focus" class="badge-icon"></i> Focus</button>` : ''}
                    </div>
                </div>`;
            }).join('');
        } else {
            criticalListHtml = '<div class="risk-item-empty">No critical vulnerabilities detected.</div>';
        }

        // Render Exploits/PoCs list HTML
        let pocListHtml = '';
        if (allExploits.length > 0) {
            pocListHtml = allExploits.map(exp => {
                const isGithub = String(exp.source || '').toLowerCase().includes('github');
                const sourceClass = isGithub ? 'github' : 'exploitdb';
                const sourceLabel = isGithub ? 'GitHub' : 'ExploitDB';
                
                return `
                <div class="risk-item-card exploit-item-box">
                    <div class="risk-card-top">
                        <div class="risk-card-title">
                            <span class="cve-code" style="color: #ffa502;">${exp.cve_id}</span>
                            <span class="mini-badge ${sourceClass}">${sourceLabel}</span>
                            ${exp.verified ? '<span class="mini-badge verified">Verified</span>' : ''}
                        </div>
                    </div>
                    <div class="exploit-title-text">${exp.title}</div>
                    ${(exp.author || exp.date || exp.exploit_type) ? `
                    <div class="risk-card-meta-tags">
                        ${exp.author ? `<span class="meta-tag">Author: ${exp.author}</span>` : ''}
                        ${exp.date ? `<span class="meta-tag">Date: ${exp.date}</span>` : ''}
                        ${exp.exploit_type ? `<span class="meta-tag">Type: ${exp.exploit_type}</span>` : ''}
                    </div>` : ''}
                    <div class="risk-card-links">
                        <a href="${exp.url}" target="_blank" rel="noopener" class="risk-link-btn primary"><i data-lucide="external-link" class="badge-icon"></i> View PoC</a>
                        ${exp.vuln_id ? `<button type="button" class="risk-focus-btn" onclick="window.dashboard.focusNode('${exp.vuln_id}')"><i data-lucide="focus" class="badge-icon"></i> Focus Vuln</button>` : ''}
                    </div>
                </div>`;
            }).join('');
        } else {
            pocListHtml = '<div class="risk-item-empty">No public exploits/PoCs identified.</div>';
        }

        // Render Exposed Services list HTML (if applicable)
        let servicesAccordionHtml = '';
        if (connectedServices.length > 0) {
            const servicesListHtml = connectedServices.map(srv => {
                const portProto = `${srv.port}/${(srv.protocol || 'tcp').toUpperCase()}`;
                const name = srv.service || srv.product || 'Unknown';
                const version = srv.version ? `v${srv.version}` : '';

                // Find service host IP if inspecting a cluster/network/target node
                let srvHost = nodeData.type === 'ip' ? nodeData.ip : '';
                if (!srvHost && elements && Array.isArray(elements.edges) && Array.isArray(elements.nodes)) {
                    const edge = elements.edges.find(e => e && e.data && e.data.target === srv.id && e.data.label === 'EXPOSES');
                    if (edge) {
                        const parentIpNode = elements.nodes.find(n => n && n.data && n.data.id === edge.data.source);
                        if (parentIpNode && parentIpNode.data) {
                            srvHost = parentIpNode.data.ip || parentIpNode.data.name || '';
                        }
                    }
                }
                if (!srvHost && nodeData.name && nodeData.name.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                    srvHost = nodeData.name;
                }

                // Check wildcard *http* strictly against banner, service name or type
                const bannerStr = String(srv.banner || '').toLowerCase();
                const serviceStr = String(srv.service || '').toLowerCase();
                const productStr = String(srv.product || '').toLowerCase();
                const isHttpBanner = bannerStr.includes('http') || serviceStr.includes('http') || productStr.includes('http') || srv.type === 'http' || srv.type === 'https';

                // Determine web URL if service is confirmed HTTP
                let serviceLinkUrl = '';
                if (isHttpBanner) {
                    if (srv.url) {
                        serviceLinkUrl = srv.url;
                    } else if (srvHost) {
                        const isHttps = srv.ssl || srv.type === 'https' || serviceStr.includes('https') || bannerStr.includes('https') || [443, 8443].includes(parseInt(srv.port));
                        const scheme = isHttps ? 'https' : 'http';
                        const portSuffix = ((scheme === 'http' && srv.port == 80) || (scheme === 'https' && srv.port == 443)) ? '' : `:${srv.port}`;
                        serviceLinkUrl = `${scheme}://${srvHost}${portSuffix}`;
                    }
                }

                return `
                <div class="risk-item-card service-item-box">
                    <div class="risk-card-top">
                        <span class="cve-code" style="color: #00d4ff;">${portProto}${srvHost && nodeData.type !== 'ip' ? ` <small style="color: #94a3b8; font-weight: normal;">(${srvHost})</small>` : ''}</span>
                        <span class="mini-badge" style="background: rgba(0,212,255,0.15); color: #00d4ff;">${name}</span>
                    </div>
                    ${(srv.product || version) ? `<div style="font-size: 0.78rem; color: #aaa; margin: 3px 0;">${srv.product || ''} ${version}</div>` : ''}
                    ${serviceLinkUrl ? `<div class="risk-card-links"><a href="${serviceLinkUrl}" target="_blank" rel="noopener" class="risk-link-btn"><i data-lucide="link" class="badge-icon"></i> ${serviceLinkUrl}</a></div>` : ''}
                    ${srv.id ? `<div class="risk-card-links" style="margin-top: 2px; border-top: none;"><button type="button" class="risk-focus-btn" onclick="window.dashboard.focusNode('${srv.id}')"><i data-lucide="focus" class="badge-icon"></i> Focus Service</button></div>` : ''}
                </div>`;
            }).join('');

            servicesAccordionHtml = `
            <div class="risk-accordion-group">
                <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this)">
                    <div class="risk-accordion-title">
                        <i data-lucide="server" class="accordion-icon ui-icon"></i>
                        <span>Exposed Services</span>
                    </div>
                    <div class="risk-accordion-status">
                        <span class="risk-pill-counter services-count" style="${connectedServices.length > 0 ? 'color: #00d4ff; background: rgba(0,212,255,0.15); border-color: rgba(0,212,255,0.4);' : ''}">${connectedServices.length}</span>
                        <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                    </div>
                </div>
                <div class="risk-accordion-body" style="display: none;">
                    ${servicesListHtml}
                </div>
            </div>`;
        }

        return `
        <div class="risk-metrics-panel">
            <h4 class="risk-metrics-heading">Risk Metrics</h4>
            
            ${servicesAccordionHtml}

            <!-- Vulnerabilities Accordion -->
            <div class="risk-accordion-group">
                <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this)">
                    <div class="risk-accordion-title">
                        <i data-lucide="shield" class="accordion-icon ui-icon"></i>
                        <span>Vulnerabilities</span>
                    </div>
                    <div class="risk-accordion-status">
                        <span class="risk-pill-counter vulns-count" style="${vulnsCount > 0 ? 'color: #ff6b6b; background: rgba(255,107,107,0.15); border-color: rgba(255,107,107,0.4);' : ''}">${vulnsCount}</span>
                        <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                    </div>
                </div>
                <div class="risk-accordion-body" style="display: none;">
                    ${vulnsListHtml}
                </div>
            </div>

            <!-- Critical Vulns Accordion -->
            <div class="risk-accordion-group">
                <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this)">
                    <div class="risk-accordion-title">
                        <i data-lucide="alert-triangle" class="accordion-icon ui-icon"></i>
                        <span>Critical Vulns</span>
                    </div>
                    <div class="risk-accordion-status">
                        <span class="risk-pill-counter critical-count" style="${criticalCount > 0 ? 'color: #ff4757; background: rgba(220,20,60,0.2); border-color: rgba(220,20,60,0.5);' : ''}">${criticalCount}</span>
                        <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                    </div>
                </div>
                <div class="risk-accordion-body" style="display: none;">
                    ${criticalListHtml}
                </div>
            </div>

            <!-- Exploits/PoCs Accordion -->
            <div class="risk-accordion-group">
                <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this)">
                    <div class="risk-accordion-title">
                        <i data-lucide="file-code" class="accordion-icon ui-icon"></i>
                        <span>Exploits/PoCs</span>
                    </div>
                    <div class="risk-accordion-status">
                        <span class="risk-pill-counter pocs-count" style="${pocCount > 0 ? 'color: #ffa502; background: rgba(243,156,18,0.15); border-color: rgba(243,156,18,0.4);' : ''}">${pocCount}</span>
                        <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                    </div>
                </div>
                <div class="risk-accordion-body" style="display: none;">
                    ${pocListHtml}
                </div>
            </div>
        </div>`;
    }

    toggleRiskAccordion(headerEl) {
        if (!headerEl) return;
        const body = headerEl.nextElementSibling;
        if (!body) return;
        
        const isHidden = body.style.display === 'none' || !body.style.display;
        if (isHidden) {
            // Find parent inspector container and close all other risk accordions
            const container = headerEl.closest('.inspector-content') || headerEl.closest('.inspector-drawer') || document.getElementById('inspector-content');
            if (container) {
                container.querySelectorAll('.risk-accordion-group').forEach(group => {
                    const groupHeader = group.querySelector('.risk-accordion-header');
                    const groupBody = group.querySelector('.risk-accordion-body');
                    if (groupHeader && groupHeader !== headerEl) {
                        groupHeader.classList.remove('open');
                        if (groupBody) groupBody.style.display = 'none';
                    }
                });
            }

            body.style.display = 'block';
            headerEl.classList.add('open');
        } else {
            body.style.display = 'none';
            headerEl.classList.remove('open');
        }
    }

    copyTextList(items, buttonEl) {
        if (!items) return;
        const textToCopy = Array.isArray(items) ? items.join('\n') : String(items).trim();
        if (!textToCopy) return;
        
        const showSuccess = () => {
            if (buttonEl) {
                const originalText = buttonEl.innerHTML;
                const hasLabel = originalText.toLowerCase().includes('copy');
                buttonEl.innerHTML = hasLabel 
                    ? '<i data-lucide="check" class="badge-icon"></i> Copied!'
                    : '<i data-lucide="check" style="width: 11px; height: 11px; color: #2ecc71;"></i>';
                buttonEl.style.background = 'rgba(39, 174, 96, 0.3)';
                buttonEl.style.borderColor = 'rgba(39, 174, 96, 0.7)';
                buttonEl.style.color = '#2ecc71';
                if (typeof lucide !== 'undefined') lucide.createIcons();
                setTimeout(() => {
                    buttonEl.innerHTML = originalText;
                    buttonEl.style.background = '';
                    buttonEl.style.borderColor = '';
                    buttonEl.style.color = '';
                    if (typeof lucide !== 'undefined') lucide.createIcons();
                }, 1800);
            }
            if (typeof this.showToast === 'function') {
                const isMultiple = Array.isArray(items) && items.length > 1;
                const msg = isMultiple 
                    ? `Copied ${items.length} items to clipboard`
                    : `Copied '${textToCopy.length > 40 ? textToCopy.substring(0, 37) + '...' : textToCopy}' to clipboard`;
                this.showToast('success', msg);
            }
        };

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(textToCopy).then(showSuccess).catch(err => {
                console.warn('Clipboard write failed, using textarea fallback', err);
                this._fallbackCopyText(textToCopy, showSuccess);
            });
        } else {
            this._fallbackCopyText(textToCopy, showSuccess);
        }
    }

    _fallbackCopyText(text, callback) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            if (callback) callback();
        } catch (err) {
            console.error('Fallback copy failed', err);
        }
        document.body.removeChild(textArea);
    }

    focusNode(nodeId) {
        if (!this.cy || !nodeId) return;
        const targetNode = this.cy.getElementById(nodeId);
        if (targetNode && targetNode.length > 0) {
            targetNode.show();
            targetNode.connectedEdges().show();
            
            this.cy.nodes().unselect();
            targetNode.select();
            
            this.cy.animate({
                center: { eles: targetNode },
                zoom: 1.4
            }, { duration: 350 });
            
            this.showNodeInspector(targetNode);
        }
    }

    showNodeInspector(node) {
        if (!node) return;
        try {
            this.selectedNode = node;
            const data = (typeof node.data === 'function') ? node.data() : (node.data || node);
            if (!data) return;

            const drawer = document.getElementById('inspector-drawer');
            const content = document.getElementById('inspector-content');
            const title = document.getElementById('inspector-title');
            if (!drawer || !content || !title) return;

            // Set title based on node type
            const nodeType = (data.type || 'UNKNOWN').toUpperCase();
            const rawType = (data.type || '').toLowerCase();
            title.textContent = `${nodeType}: ${data.label || data.name || data.id || ''}`;

            // Build content based on node type
            let html = '';
            const elements = this.graphData?.elements || (window.dashboard && window.dashboard.graphData?.elements);

        if (data.is_cluster || rawType === 'cluster_services' || rawType === 'cluster_vulns') {
            const isServiceCluster = rawType === 'cluster_services';
            title.textContent = isServiceCluster ? `SERVICES CLUSTER: ${data.count} Ports` : `VULNERABILITY CLUSTER: ${data.count} CVEs`;

            // Identify parent node
            let parentNodeId = data.parent_ip || data.parent_srv;
            let parentNode = this.cy.getElementById(parentNodeId);
            let parentData = parentNode.length ? parentNode.data() : (elements?.nodes?.find(n => (n.data || n).id === parentNodeId)?.data || {});
            
            // Gather risk metrics from parent (e.g. host IP or service)
            const riskMetricsHtml = this.renderRiskMetricsAccordion(parentData, elements);

            html = `
                <h4>Collapsed Cluster Details</h4>
                <div class="property">
                    <span class="key">Cluster Type:</span>
                    <span class="value" style="color: #00d4ff; font-weight: bold;">${isServiceCluster ? 'Exposed Services Group' : 'Vulnerabilities Group'}</span>
                </div>
                <div class="property">
                    <span class="key">Hidden Items Count:</span>
                    <span class="value" style="color: ${isServiceCluster ? '#f39c12' : '#e74c3c'}; font-weight: bold; font-size: 1.05rem;">${data.count} ${isServiceCluster ? 'Services' : 'Vulnerabilities'}</span>
                </div>
                <div class="property">
                    <span class="key">Parent Asset:</span>
                    <span class="value">${parentData.label || parentData.name || parentData.ip || parentNodeId || 'N/A'}</span>
                </div>
                ${riskMetricsHtml}
            `;
        } else if (rawType === 'domain' || rawType === 'subdomain' || rawType === 'target' || rawType === 'target_root' || rawType === 'network') {
            const riskMetricsHtml = this.renderRiskMetricsAccordion(data, elements);
            let sectionTitle = 'Domain Information';
            if (rawType === 'target' || rawType === 'target_root') sectionTitle = 'Primary Query Target';
            if (rawType === 'network') sectionTitle = 'Organization / Network Cluster';

            let fileTargetsHtml = '';
            if ((rawType === 'target' || rawType === 'target_root') && Array.isArray(data.targets_list) && data.targets_list.length > 0) {
                const targetsBadgeList = data.targets_list.map((t, idx) => `
                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 4px 8px; margin-bottom: 3px; background: rgba(0, 212, 255, 0.06); border: 1px solid rgba(0, 212, 255, 0.18); border-radius: 4px; font-family: monospace; font-size: 0.82rem;">
                        <span style="color: #00d4ff; font-weight: 500;">${t}</span>
                        <span style="color: #64748b; font-size: 0.72rem;">#${idx + 1}</span>
                    </div>
                `).join('');

                fileTargetsHtml = `
                    <div class="risk-accordion-group" style="margin-top: 0.75rem; margin-bottom: 0.5rem;">
                        <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this)">
                            <div class="risk-accordion-title">
                                <i data-lucide="list" class="accordion-icon ui-icon"></i>
                                <span>Input Targets List</span>
                            </div>
                            <div class="risk-accordion-status" style="display: flex; flex-wrap: wrap; align-items: center; gap: 6px; justify-content: flex-end;">
                                <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 212, 255, 0.2); color: #00d4ff; border-color: rgba(0, 212, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(data.targets_list).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i></button>
                                <span class="risk-pill-counter" style="color: #00d4ff; background: rgba(0,212,255,0.15); border-color: rgba(0,212,255,0.4);">${data.targets_list.length}</span>
                                <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                            </div>
                        </div>
                        <div class="risk-accordion-body" style="display: none; max-height: 220px; overflow-y: auto; padding: 8px 6px;">
                            ${targetsBadgeList}
                        </div>
                    </div>
                `;
            }

            // Root Target: Enumerated Domains, Enumerated Subdomains, and CLI Audit Logs
            let rootDomainsAccordionHtml = '';
            let rootSubdomainsAccordionHtml = '';
            let rootIpsAccordionHtml = '';
            let rootScanLogsAccordionHtml = '';

            if (rawType === 'target' || rawType === 'target_root' || data.is_root === true) {
                const allDoms = Array.isArray(data.all_domains) ? data.all_domains : [];
                if (allDoms.length > 0) {
                    const domNames = allDoms.map(d => d.name);
                    const allMarked = domNames.length > 0 && domNames.every(name => this.isTargetMarked(name));
                    const domListHtml = allDoms.map(d => {
                        const isMarked = this.isTargetMarked(d.name);
                        return `
                            <div class="root-domain-item" data-domain="${(d.name || '').toLowerCase()}" style="display: flex; align-items: center; justify-content: space-between; padding: 5px 8px; margin-bottom: 4px; background: rgba(0, 180, 216, 0.08); border: 1px solid rgba(0, 180, 216, 0.25); border-radius: 4px; font-family: monospace; font-size: 0.8rem;">
                                <span style="color: #00b4d8; font-weight: 600; word-break: break-all;">${d.name}</span>
                                <div style="display: flex; gap: 4px; align-items: center;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${d.name}')" title="${isMarked ? 'Remove Target' : 'Set as Target (FQDN)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i>
                                    </button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: #00b4d8; border-color: rgba(0, 180, 216, 0.4); background: rgba(0, 180, 216, 0.15);" onclick="event.stopPropagation(); window.dashboard.copyTextList('${d.name}', this)" title="Copy Domain">
                                        <i data-lucide="copy" style="width: 10px; height: 10px;"></i>
                                    </button>
                                </div>
                            </div>
                        `;
                    }).join('');

                    rootDomainsAccordionHtml = `
                        <div class="risk-accordion-group" style="margin-top: 0.75rem; margin-bottom: 0.5rem;">
                            <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this)">
                                <div class="risk-accordion-title">
                                    <i data-lucide="globe" class="accordion-icon ui-icon"></i>
                                    <span>Enumerated Domains (${allDoms.length})</span>
                                </div>
                                <div class="risk-accordion-status" style="display: flex; flex-wrap: wrap; align-items: center; gap: 6px; justify-content: flex-end;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; color: ${allMarked ? '#ef4444' : '#00f0ff'}; border-color: ${allMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${allMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="event.stopPropagation(); window.dashboard.${allMarked ? 'removeTargetsBulk' : 'setTargetsBulk'}(${JSON.stringify(domNames).replace(/"/g, '&quot;')})" title="${allMarked ? 'Remove all from Targets' : 'Set all items as Target'}"><i data-lucide="crosshair" class="badge-icon"></i></button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(0, 180, 216, 0.2); color: #00b4d8; border-color: rgba(0, 180, 216, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(domNames).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i></button>
                                    <span class="risk-pill-counter" style="color: #00b4d8; background: rgba(0, 180, 216, 0.15); border-color: rgba(0, 180, 216, 0.4);">${allDoms.length}</span>
                                    <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                                </div>
                            </div>
                            <div class="risk-accordion-body" style="display: none; max-height: 250px; overflow-y: auto; padding: 8px 6px;">
                                <div style="margin-bottom: 6px;">
                                    <input type="text" placeholder="Filter domains..." oninput="window.dashboard.filterRootDomains(this.value)" style="width: 100%; box-sizing: border-box; padding: 4px 8px; font-size: 0.78rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: #f8fafc;">
                                </div>
                                <div id="root-domains-list-container">
                                    ${domListHtml}
                                </div>
                            </div>
                        </div>
                    `;
                }

                const allSubs = Array.isArray(data.all_subdomains) ? data.all_subdomains : [];
                if (allSubs.length > 0) {
                    const subNames = allSubs.map(s => s.name);
                    const allMarked = subNames.length > 0 && subNames.every(name => this.isTargetMarked(name));
                    const subListHtml = allSubs.map(s => {
                        const isMarked = this.isTargetMarked(s.name);
                        const ipsBadges = (s.resolved_ips || s.ips || []).map(ipObj => {
                            const ipStr = typeof ipObj === 'string' ? ipObj : (ipObj.ip || '');
                            if (!ipStr) return '';
                            return `<span style="font-family: monospace; font-size: 0.7rem; color: #93c5fd; background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 3px; padding: 1px 4px;">${ipStr}</span>`;
                        }).join('');

                        return `
                            <div class="root-subdomain-item" data-subdomain="${(s.name || '').toLowerCase()}" style="display: flex; flex-direction: column; gap: 4px; padding: 6px 8px; margin-bottom: 5px; background: rgba(78, 205, 196, 0.07); border: 1px solid rgba(78, 205, 196, 0.22); border-radius: 4px;">
                                <div style="display: flex; align-items: center; justify-content: space-between;">
                                    <span style="font-family: monospace; font-size: 0.8rem; color: #4ecdc4; font-weight: 600; word-break: break-all;">${s.name}</span>
                                <div style="display: flex; gap: 4px; align-items: center;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${s.name}')" title="${isMarked ? 'Remove Target' : 'Set as Target (FQDN)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i>
                                    </button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4); background: rgba(78, 205, 196, 0.15);" onclick="event.stopPropagation(); window.dashboard.copyTextList('${s.name}', this)" title="Copy Subdomain">
                                        <i data-lucide="copy" style="width: 10px; height: 10px;"></i>
                                    </button>
                                </div>
                                </div>
                                ${ipsBadges ? `<div style="display: flex; flex-wrap: wrap; gap: 3px; align-items: center;">${ipsBadges}</div>` : ''}
                            </div>
                        `;
                    }).join('');

                    rootSubdomainsAccordionHtml = `
                        <div class="risk-accordion-group" style="margin-top: 0.75rem; margin-bottom: 0.5rem;">
                            <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this)">
                                <div class="risk-accordion-title">
                                    <i data-lucide="globe" class="accordion-icon ui-icon"></i>
                                    <span>Enumerated Subdomains (${allSubs.length})</span>
                                </div>
                                <div class="risk-accordion-status" style="display: flex; flex-wrap: wrap; align-items: center; gap: 6px; justify-content: flex-end;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; color: ${allMarked ? '#ef4444' : '#00f0ff'}; border-color: ${allMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${allMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="event.stopPropagation(); window.dashboard.${allMarked ? 'removeTargetsBulk' : 'setTargetsBulk'}(${JSON.stringify(subNames).replace(/"/g, '&quot;')})" title="${allMarked ? 'Remove all from Targets' : 'Set all items as Target'}"><i data-lucide="crosshair" class="badge-icon"></i></button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(78, 205, 196, 0.2); color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(subNames).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i></button>
                                    <span class="risk-pill-counter" style="color: #4ecdc4; background: rgba(78, 205, 196, 0.15); border-color: rgba(78, 205, 196, 0.4);">${allSubs.length}</span>
                                    <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                                </div>
                            </div>
                            <div class="risk-accordion-body" style="display: none; max-height: 280px; overflow-y: auto; padding: 8px 6px;">
                                <div style="margin-bottom: 6px;">
                                    <input type="text" placeholder="Filter subdomains..." oninput="window.dashboard.filterRootSubdomains(this.value)" style="width: 100%; box-sizing: border-box; padding: 4px 8px; font-size: 0.78rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: #f8fafc;">
                                </div>
                                <div id="root-subdomains-list-container">
                                    ${subListHtml}
                                </div>
                            </div>
                        </div>
                    `;
                }

                const allIps = Array.isArray(data.all_ips) ? data.all_ips : [];
                if (allIps.length > 0) {
                    const ipStrings = allIps.map(item => item.ip);
                    const allMarked = ipStrings.length > 0 && ipStrings.every(ip => this.isTargetMarked(ip));
                    const ipListHtml = allIps.map(item => {
                        const isMarked = this.isTargetMarked(item.ip);
                        const fqdnsBadges = (item.fqdns || []).slice(0, 3).map(f => `
                            <span style="font-family: monospace; font-size: 0.68rem; color: #4ecdc4; background: rgba(78, 205, 196, 0.12); border: 1px solid rgba(78, 205, 196, 0.25); border-radius: 3px; padding: 1px 4px;">${f}</span>
                        `).join('');
                        const extraFqdns = (item.fqdn_count || 0) > 3 ? `<span style="font-size: 0.68rem; color: #94a3b8;">+${item.fqdn_count - 3}</span>` : '';

                        return `
                            <div class="root-ip-item" data-ip="${(item.ip || '').toLowerCase()}" data-org="${(item.org || '').toLowerCase()}" style="display: flex; flex-direction: column; gap: 4px; padding: 6px 8px; margin-bottom: 5px; background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.25); border-radius: 4px;">
                                <div style="display: flex; align-items: center; justify-content: space-between;">
                                    <div style="display: flex; align-items: center; gap: 6px;">
                                        <span style="font-family: monospace; font-size: 0.82rem; color: #60a5fa; font-weight: bold;">${item.ip}</span>
                                        ${item.country && item.country !== 'Unknown' ? `<span style="font-size: 0.7rem; color: #94a3b8;">(${item.country})</span>` : ''}
                                    </div>
                                <div style="display: flex; gap: 4px; align-items: center;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${item.ip}')" title="${isMarked ? 'Remove Target' : 'Set as Target (IP)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i>
                                    </button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: #60a5fa; border-color: rgba(59, 130, 246, 0.4); background: rgba(59, 130, 246, 0.15);" onclick="event.stopPropagation(); window.dashboard.copyTextList('${item.ip}', this)" title="Copy IP">
                                        <i data-lucide="copy" style="width: 10px; height: 10px;"></i>
                                    </button>
                                </div>
                                </div>
                                ${item.org && item.org !== 'Unknown' ? `<div style="font-size: 0.72rem; color: #cbd5e1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">🏢 ${this.escapeHtml(item.org)}</div>` : ''}
                                ${fqdnsBadges ? `<div style="display: flex; flex-wrap: wrap; gap: 3px; align-items: center;">${fqdnsBadges} ${extraFqdns}</div>` : ''}
                            </div>
                        `;
                    }).join('');

                    rootIpsAccordionHtml = `
                        <div class="risk-accordion-group" style="margin-top: 0.75rem; margin-bottom: 0.5rem;">
                            <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this)">
                                <div class="risk-accordion-title">
                                    <i data-lucide="server" class="accordion-icon ui-icon" style="color: #60a5fa;"></i>
                                    <span>Enumerated Host IPs (${allIps.length})</span>
                                </div>
                                <div class="risk-accordion-status" style="display: flex; flex-wrap: wrap; align-items: center; gap: 6px; justify-content: flex-end;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; color: ${allMarked ? '#ef4444' : '#00f0ff'}; border-color: ${allMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${allMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="event.stopPropagation(); window.dashboard.${allMarked ? 'removeTargetsBulk' : 'setTargetsBulk'}(${JSON.stringify(ipStrings).replace(/"/g, '&quot;')})" title="${allMarked ? 'Remove all from Targets' : 'Set all items as Target'}"><i data-lucide="crosshair" class="badge-icon"></i></button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(59, 130, 246, 0.2); color: #60a5fa; border-color: rgba(59, 130, 246, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(ipStrings).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i></button>
                                    <span class="risk-pill-counter" style="color: #60a5fa; background: rgba(59, 130, 246, 0.15); border-color: rgba(59, 130, 246, 0.4);">${allIps.length}</span>
                                    <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                                </div>
                            </div>
                            <div class="risk-accordion-body" style="display: none; max-height: 280px; overflow-y: auto; padding: 8px 6px;">
                                <div style="margin-bottom: 6px;">
                                    <input type="text" placeholder="Filter IPs or org..." oninput="window.dashboard.filterRootIps(this.value)" style="width: 100%; box-sizing: border-box; padding: 4px 8px; font-size: 0.78rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: #f8fafc;">
                                </div>
                                <div id="root-ips-list-container">
                                    ${ipListHtml}
                                </div>
                            </div>
                        </div>
                    `;
                }

                // CLI Execution Logs & Audit Trail Accordion for Root Target
                rootScanLogsAccordionHtml = `
                    <div class="risk-accordion-group" style="margin-top: 0.75rem; margin-bottom: 0.5rem;">
                        <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this); window.dashboard.loadRootAuditLogs()">
                            <div class="risk-accordion-title">
                                <i data-lucide="terminal" class="accordion-icon ui-icon" style="color: #8C52FF;"></i>
                                <span style="color: #e9d5ff;">CLI Execution &amp; Audit Logs</span>
                            </div>
                            <div class="risk-accordion-status" style="display: flex; flex-wrap: wrap; align-items: center; gap: 6px; justify-content: flex-end;">
                                <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(140, 82, 255, 0.2); color: #e9d5ff; border-color: rgba(140, 82, 255, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyRootAuditLogs(this)"><i data-lucide="copy" class="badge-icon"></i></button>
                                <span id="root-audit-logs-count" class="risk-pill-counter" style="color: #8C52FF; background: rgba(140, 82, 255, 0.15); border-color: rgba(140, 82, 255, 0.4);">...</span>
                                <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                            </div>
                        </div>
                        <div class="risk-accordion-body" style="display: none; max-height: 320px; overflow-y: auto; padding: 8px 6px; background: #0c0a14; border-top: 1px solid rgba(140, 82, 255, 0.2);">
                            <div style="margin-bottom: 6px; display: flex; gap: 6px;">
                                <input type="text" id="root-audit-logs-filter" placeholder="Filter CLI logs (e.g. shodan, masscan, nuclei)..." oninput="window.dashboard.filterRootAuditLogs(this.value)" style="flex: 1; box-sizing: border-box; padding: 4px 8px; font-size: 0.78rem; background: #171425; border: 1px solid rgba(140, 82, 255, 0.3); border-radius: 4px; color: #f8fafc; font-family: monospace;">
                                <button type="button" class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 0.72rem; background: rgba(140, 82, 255, 0.15); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.3); border-radius: 4px;" onclick="window.dashboard.loadRootAuditLogs('', true)">
                                    <i data-lucide="refresh-cw" style="width: 11px; height: 11px;"></i>
                                </button>
                            </div>
                            <div id="root-audit-logs-container" style="font-family: 'JetBrains Mono', monospace, Consolas; font-size: 0.75rem; line-height: 1.45; color: #cbd5e1; background: #090710; border: 1px solid rgba(255,255,255,0.06); border-radius: 4px; padding: 8px; max-height: 240px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;">
                                <div style="color: #64748b; font-style: italic;">Loading execution audit trail...</div>
                            </div>
                        </div>
                    </div>
                `;
            }

            let subdomainsAccordionHtml = '';
            if (rawType === 'domain' || rawType === 'subdomain') {
                let relatedSubs = Array.isArray(data.related_subdomains) ? data.related_subdomains : [];

                if (relatedSubs.length > 0) {
                    const subNamesList = relatedSubs.map(s => s.name || s.label || s.id.replace(/^(dom_|sub_)/, ''));
                    const allMarked = subNamesList.length > 0 && subNamesList.every(name => this.isTargetMarked(name));
                    const subListHtml = relatedSubs.map((sub) => {
                        const subName = sub.name || sub.label || sub.id.replace(/^(dom_|sub_)/, '');
                        const isMarked = this.isTargetMarked(subName);
                        const ipsBadges = (sub.resolved_ips || sub.ips || []).map(ipObj => {
                            const ipStr = typeof ipObj === 'string' ? ipObj : (ipObj.ip || '');
                            if (!ipStr) return '';
                            return `<span style="font-family: monospace; font-size: 0.68rem; color: #93c5fd; background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 3px; padding: 1px 4px;">${ipStr}</span>`;
                        }).join('');

                        return `
                            <div class="domain-subdomain-item" data-subdomain="${(subName || '').toLowerCase()}" style="display: flex; flex-direction: column; gap: 4px; padding: 6px 8px; margin-bottom: 5px; background: rgba(78, 205, 196, 0.07); border: 1px solid rgba(78, 205, 196, 0.22); border-radius: 4px;">
                                <div style="display: flex; align-items: center; justify-content: space-between;">
                                    <span style="font-family: monospace; font-size: 0.8rem; color: #4ecdc4; font-weight: 600; word-break: break-all;">${subName}</span>
                                <div style="display: flex; gap: 4px; align-items: center;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: ${isMarked ? '#ef4444' : '#00f0ff'}; border-color: ${isMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${isMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="window.dashboard.toggleTargetMark('${subName}')" title="${isMarked ? 'Remove Target' : 'Set as Target (FQDN)'}">
                                        <i data-lucide="crosshair" style="width: 10px; height: 10px;"></i>
                                    </button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem; color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4); background: rgba(78, 205, 196, 0.15);" onclick="event.stopPropagation(); window.dashboard.copyTextList('${subName}', this)" title="Copy Subdomain">
                                        <i data-lucide="copy" style="width: 10px; height: 10px;"></i>
                                    </button>
                                </div>
                                </div>
                                ${ipsBadges ? `<div style="display: flex; flex-wrap: wrap; gap: 3px; align-items: center;">${ipsBadges}</div>` : ''}
                            </div>
                        `;
                    }).join('');

                    const accordionTitle = rawType === 'subdomain' ? 'Child Subdomains' : 'Related Subdomains';
                    subdomainsAccordionHtml = `
                        <div class="risk-accordion-group" style="margin-top: 0.75rem; margin-bottom: 0.5rem;">
                            <div class="risk-accordion-header" onclick="window.dashboard.toggleRiskAccordion(this)">
                                <div class="risk-accordion-title">
                                    <i data-lucide="globe" class="accordion-icon ui-icon"></i>
                                    <span>${accordionTitle} (${relatedSubs.length})</span>
                                </div>
                                <div class="risk-accordion-status" style="display: flex; flex-wrap: wrap; align-items: center; gap: 6px; justify-content: flex-end;">
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; color: ${allMarked ? '#ef4444' : '#00f0ff'}; border-color: ${allMarked ? '#ef4444' : 'rgba(0, 240, 255, 0.4)'}; background: ${allMarked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.15)'};" onclick="event.stopPropagation(); window.dashboard.${allMarked ? 'removeTargetsBulk' : 'setTargetsBulk'}(${JSON.stringify(subNamesList).replace(/"/g, '&quot;')})" title="${allMarked ? 'Remove all from Targets' : 'Set all items as Target'}"><i data-lucide="crosshair" class="badge-icon"></i></button>
                                    <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 7px; font-size: 0.75rem; background: rgba(78, 205, 196, 0.2); color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4);" onclick="event.stopPropagation(); window.dashboard.copyTextList(${JSON.stringify(subNamesList).replace(/"/g, '&quot;')}, this)"><i data-lucide="copy" class="badge-icon"></i></button>
                                    <span class="risk-pill-counter" style="color: #4ecdc4; background: rgba(78, 205, 196, 0.15); border-color: rgba(78, 205, 196, 0.4);">${relatedSubs.length}</span>
                                    <i data-lucide="chevron-down" class="accordion-chevron ui-icon"></i>
                                </div>
                            </div>
                            <div class="risk-accordion-body" style="display: none; max-height: 250px; overflow-y: auto; padding: 8px 6px;">
                                <div style="margin-bottom: 6px;">
                                    <input type="text" placeholder="Filter related subdomains..." oninput="window.dashboard.filterDomainSubdomains(this.value)" style="width: 100%; box-sizing: border-box; padding: 4px 8px; font-size: 0.78rem; background: #0f172a; border: 1px solid #334155; border-radius: 4px; color: #f8fafc;">
                                </div>
                                <div id="domain-subdomains-list-container">
                                    ${subListHtml}
                                </div>
                            </div>
                        </div>
                    `;
                }
            }

            let resolvedIpsHtml = '';
            if (rawType === 'domain' || rawType === 'subdomain') {
                const resolvedIps = data.resolved_ips || [];

                if (resolvedIps.length > 0) {
                    const ipsBadges = resolvedIps.map(item => {
                        const isMarked = this.markedTargets.has(item.ip);
                        const targetColor = isMarked ? '#ef4444' : '#93c5fd';
                        const targetBg = isMarked ? 'rgba(239, 68, 68, 0.25)' : 'rgba(59, 130, 246, 0.25)';
                        return `
                        <span style="display: inline-flex; align-items: center; gap: 4px; padding: 2px 6px; background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 4px; font-family: monospace; font-size: 0.8rem; color: #60a5fa; margin-right: 4px; margin-bottom: 2px;">
                            ${item.ip}
                            <button type="button" class="risk-focus-btn" style="margin: 0; padding: 1px 4px; font-size: 0.65rem; background: ${targetBg}; color: ${targetColor}; border: none; border-radius: 2px; cursor: pointer;" onclick="event.stopPropagation(); window.dashboard.toggleTargetMark('${item.ip}')" title="${isMarked ? 'Remove Target' : 'Set as Target (IP)'}"><i data-lucide="crosshair" style="width: 10px; height: 10px;"></i></button>
                            <button type="button" class="risk-focus-btn" style="margin: 0; padding: 1px 4px; font-size: 0.65rem; background: rgba(59, 130, 246, 0.25); color: #93c5fd; border: none; border-radius: 2px; cursor: pointer;" onclick="event.stopPropagation(); window.dashboard.focusNode('${item.id}')" title="Focus IP in graph"><i data-lucide="focus" style="width: 10px; height: 10px;"></i></button>
                        </span>
                        `;
                    }).join('');

                    resolvedIpsHtml = `
                    <div class="property">
                        <span class="key">${resolvedIps.length === 1 ? 'Resolved IP:' : 'Resolved IPs:'}</span>
                        <div class="value" style="display: flex; flex-wrap: wrap; gap: 4px; align-items: center;">${ipsBadges}</div>
                    </div>`;
                } else {
                    resolvedIpsHtml = `
                    <div class="property">
                        <span class="key">Resolved IP:</span>
                        <span class="value" style="color: #94a3b8; font-style: italic;">Unresolved / None</span>
                    </div>`;
                }
            }

            let mainPropertiesHtml = '';
            if (rawType === 'network') {
                mainPropertiesHtml = `
                <div class="property">
                    <span class="key">Organization:</span>
                    <span class="value">${data.org || data.name || data.label}</span>
                </div>
                ${data.asn ? `
                <div class="property">
                    <span class="key">Autonomous System (ASN):</span>
                    <span class="value" style="color: #60a5fa; font-weight: 600; font-family: monospace;">${data.asn}</span>
                </div>` : ''}
                <div class="property">
                    <span class="key">Type:</span>
                    <span class="value">ORGANIZATION / ASN CLUSTER</span>
                </div>`;
            } else {
                mainPropertiesHtml = `
                <div class="property">
                    <span class="key">${(rawType === 'target' || rawType === 'target_root') ? 'Target Query:' : 'Domain / Host:'}</span>
                    <span class="value">${data.name || data.label}</span>
                </div>
                ${resolvedIpsHtml}
                <div class="property">
                    <span class="key">Type:</span>
                    <span class="value">${data.target_type ? `${data.type.toUpperCase()} (${data.target_type.toUpperCase()})` : data.type.toUpperCase()}</span>
                </div>`;
            }

            html = `
                <h4>${sectionTitle}</h4>
                ${mainPropertiesHtml}
                ${fileTargetsHtml}
                ${rootDomainsAccordionHtml}
                ${rootSubdomainsAccordionHtml}
                ${rootIpsAccordionHtml}
                ${rootScanLogsAccordionHtml}
                ${subdomainsAccordionHtml}
                ${riskMetricsHtml}
            `;
        } else if (rawType === 'ip') {
            const riskMetricsHtml = this.renderRiskMetricsAccordion(data, elements);
            const ipVal = String(data.ip || data.label || data.name || data.id || '').replace(/^ip_/, '').trim();
            const isMarked = this.isTargetMarked(ipVal);

            let cityHtml = '';
            if (data.city || data.region_code) {
                const cityRegion = [data.city, data.region_code].filter(Boolean).join(', ');
                cityHtml = `
                <div class="property">
                    <span class="key">City / State:</span>
                    <span class="value">${cityRegion}</span>
                </div>`;
            }

            let geoHtml = '';
            const lat = (data.latitude !== null && data.latitude !== undefined && data.latitude !== '') ? Number(data.latitude) : null;
            const lon = (data.longitude !== null && data.longitude !== undefined && data.longitude !== '') ? Number(data.longitude) : null;
            if (lat !== null && lon !== null && !isNaN(lat) && !isNaN(lon)) {
                const mapsUrl = `https://www.google.com/maps?q=${lat},${lon}`;
                geoHtml = `
                <div class="property">
                    <span class="key">Geolocation:</span>
                    <span class="value" style="display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap;">
                        <span>${lat.toFixed(4)}, ${lon.toFixed(4)}</span>
                        <a href="${mapsUrl}" target="_blank" rel="noopener noreferrer" style="display: inline-flex; align-items: center; gap: 0.25rem; font-size: 0.72rem; color: #00d4ff; background: rgba(0, 212, 255, 0.1); border: 1px solid rgba(0, 212, 255, 0.3); border-radius: 4px; padding: 0.15rem 0.45rem; text-decoration: none; transition: all 0.2s;" onmouseover="this.style.background='rgba(0,212,255,0.2)'" onmouseout="this.style.background='rgba(0,212,255,0.1)'">
                            <i data-lucide="map-pin" style="width: 11px; height: 11px;"></i> Map
                        </a>
                    </span>
                </div>`;
            }

            // Collect all resolving domains/subdomains for this IP (from graph edges and direct node metadata)
            const resolvingDomains = [];
            const seenFqdns = new Set();

            // 1. From direct fqdns array in node data
            if (Array.isArray(data.fqdns)) {
                data.fqdns.forEach(fqdn => {
                    const fClean = String(fqdn || '').trim();
                    if (fClean && !seenFqdns.has(fClean.toLowerCase())) {
                        seenFqdns.add(fClean.toLowerCase());
                        resolvingDomains.push({ id: null, name: fClean, type: 'subdomain' });
                    }
                });
            }

            // 2. From cytoscape graph incomers (if present)
            if (this.cy) {
                const ipNode = this.cy.getElementById(data.id);
                if (ipNode.length > 0) {
                    ipNode.incomers('node[type="subdomain"], node[type="domain"]').forEach(dNode => {
                        const dData = dNode.data();
                        const dName = (dData.name || dData.label || '').trim();
                        if (dName) {
                            const lower = dName.toLowerCase();
                            const existing = resolvingDomains.find(r => r.name.toLowerCase() === lower);
                            if (existing) {
                                existing.id = dNode.id();
                                existing.type = dData.type;
                            } else if (!seenFqdns.has(lower)) {
                                seenFqdns.add(lower);
                                resolvingDomains.push({ id: dNode.id(), name: dName, type: dData.type });
                            }
                        }
                    });
                }
            }
            if (resolvingDomains.length === 0 && elements && elements.edges) {
                const inEdges = this.inEdges ? (this.inEdges.get(data.id) || []) : [];
                inEdges.forEach(edgeData => {
                    if (['RESOLVES_TO', 'IPS_HISTORY', 'HOSTS_IP', 'CONTAINS_IP'].includes(edgeData.label)) {
                        const srcData = this.nodeIndex ? this.nodeIndex.get(edgeData.source) : null;
                        if (srcData && (srcData.type === 'domain' || srcData.type === 'subdomain')) {
                            const dName = srcData.name || srcData.label;
                            if (dName && !seenFqdns.has(dName.toLowerCase())) {
                                seenFqdns.add(dName.toLowerCase());
                                resolvingDomains.push({ id: edgeData.source, name: dName, type: srcData.type });
                            }
                        }
                    }
                });
            }

            let resolvingDomainsHtml = '';
            if (resolvingDomains.length > 0) {
                const totalFqdns = resolvingDomains.length;
                const showSearch = totalFqdns > 5;
                const searchHtml = showSearch ? `
                    <div style="margin-bottom: 6px;">
                        <input type="text" id="ip-fqdn-filter-input" placeholder="🔍 Filter ${totalFqdns} FQDNs / Virtual Hosts..." 
                            style="width: 100%; padding: 4px 8px; background: rgba(0,0,0,0.35); border: 1px solid rgba(78, 205, 196, 0.3); border-radius: 4px; color: #fff; font-size: 0.75rem; outline: none;"
                            oninput="window.dashboard.filterIpFqdnList(this.value)"
                        />
                    </div>
                ` : '';

                const actionToolbar = `
                    <div style="display: flex; gap: 6px; margin-bottom: 6px; flex-wrap: wrap;">
                        <button type="button" class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 0.72rem; border-radius: 4px; display: inline-flex; align-items: center; gap: 4px; background: rgba(255,255,255,0.06); color: #fff; border: 1px solid rgba(255,255,255,0.15);" onclick="window.dashboard.copyFqdnsList('${data.id}', this)">
                            <i data-lucide="copy" style="width: 12px; height: 12px;"></i> Copy All (${totalFqdns})
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 0.72rem; border-radius: 4px; display: inline-flex; align-items: center; gap: 4px; background: rgba(0,240,255,0.1); color: #00f0ff; border: 1px solid rgba(0,240,255,0.3);" onclick="window.dashboard.targetAllIpFqdns('${data.id}')">
                            <i data-lucide="crosshair" style="width: 12px; height: 12px;"></i> Target All FQDNs
                        </button>
                    </div>
                `;

                const domBadges = resolvingDomains.map(item => {
                    const isTarget = this.isTargetMarked(item.name);
                    const targetBtnStyle = isTarget 
                        ? 'background: rgba(0, 240, 255, 0.25); color: #00f0ff; border-color: #00f0ff;' 
                        : 'background: rgba(255, 255, 255, 0.05); color: var(--text-muted); border-color: rgba(255, 255, 255, 0.15);';
                    const targetBtnText = isTarget ? 'Targeted' : 'Target';

                    const focusBtn = item.id ? `
                        <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 5px; font-size: 0.68rem; background: rgba(78, 205, 196, 0.2); color: #4ecdc4; border-color: rgba(78, 205, 196, 0.4); border-radius: 3px; border: 1px solid;" onclick="event.stopPropagation(); window.dashboard.focusNode('${item.id}')" title="Focus domain in graph">
                            <i data-lucide="focus" style="width: 10px; height: 10px;"></i>
                        </button>
                    ` : '';

                    return `
                    <div class="ip-fqdn-item" data-fqdn="${(item.name || "").toLowerCase()}" style="display: flex; align-items: center; justify-content: space-between; padding: 4px 6px; margin-bottom: 3px; background: rgba(78, 205, 196, 0.06); border: 1px solid rgba(78, 205, 196, 0.2); border-radius: 4px; font-family: monospace; font-size: 0.76rem;">
                        <span style="color: #4ecdc4; font-weight: 500; word-break: break-all; margin-right: 6px;">${item.name}</span>
                        <div style="display: flex; align-items: center; gap: 4px; flex-shrink: 0;">
                            ${focusBtn}
                            <button type="button" style="margin: 0; padding: 2px 6px; font-size: 0.68rem; border-radius: 3px; border: 1px solid; cursor: pointer; transition: all 0.2s; ${targetBtnStyle}" onclick="event.stopPropagation(); window.dashboard.toggleTargetMark('${item.name}')" title="Toggle as target">
                                ${targetBtnText}
                            </button>
                            <button type="button" style="margin: 0; padding: 2px 6px; font-size: 0.68rem; background: rgba(255,255,255,0.08); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.2); border-radius: 3px; cursor: pointer;" onclick="event.stopPropagation(); window.dashboard.copyTextList('${item.name}', this);" title="Copy FQDN">
                                <i data-lucide="copy" style="width: 10px; height: 10px;"></i>
                            </button>
                        </div>
                    </div>
                `}).join('');

                resolvingDomainsHtml = `
                <div class="property" style="flex-direction: column; align-items: flex-start; gap: 4px; margin-top: 0.5rem; margin-bottom: 0.5rem; background: rgba(0,0,0,0.2); padding: 8px; border-radius: 6px; border: 1px solid rgba(78, 205, 196, 0.2);">
                    <div style="display: flex; justify-content: space-between; align-items: center; width: 100%; margin-bottom: 4px;">
                        <span class="key" style="color: #4ecdc4; font-weight: 600;">🌐 Associated FQDNs &amp; VHosts (${totalFqdns})</span>
                    </div>
                    ${actionToolbar}
                    ${searchHtml}
                    <div id="ip-fqdn-list-container" style="width: 100%; max-height: 200px; overflow-y: auto; padding-right: 2px;">
                        ${domBadges}
                    </div>
                </div>`;
            }

            html = `
                <h4>IP Address Information</h4>
                <div class="property">
                    <span class="key">IP Address:</span>
                    <span class="value">${data.ip || ipVal}</span>
                </div>
                ${resolvingDomainsHtml}
                <div class="property">
                    <span class="key">Organization:</span>
                    <span class="value">${data.org || 'Unknown'}</span>
                </div>
                ${cityHtml}
                <div class="property">
                    <span class="key">Country:</span>
                    <span class="value">${data.country || 'Unknown'}</span>
                </div>
                ${geoHtml}
                <div class="property">
                    <span class="key">ASN:</span>
                    <span class="value">${data.asn || 'Unknown'}</span>
                </div>
                ${riskMetricsHtml}
            `;
        } else if (rawType === 'service' || rawType === 'http' || rawType === 'https') {
            let urlHtml = '';
            let hostHtml = '';
            let displayUrl = data.url;
            let host = '';
            
            try {
                const bannerStr = String(data.banner || '').toLowerCase();
                const serviceStr = String(data.service || '').toLowerCase();
                const productStr = String(data.product || '').toLowerCase();
                const isHttpService = bannerStr.includes('http') || serviceStr.includes('http') || productStr.includes('http') || rawType === 'http' || rawType === 'https';

                if (elements && Array.isArray(elements.edges) && Array.isArray(elements.nodes)) {
                    const edge = elements.edges.find(e => e && e.data && e.data.target === data.id);
                    if (edge) {
                        const parentNode = elements.nodes.find(n => n && n.data && n.data.id === edge.data.source);
                        if (parentNode && parentNode.data) {
                            host = parentNode.data.ip || parentNode.data.name || parentNode.data.label || parentNode.data.id || '';
                        }
                    }
                }

                if (host) {
                    hostHtml = `
                    <div class="property">
                        <span class="key">Host:</span>
                        <span class="value">${host}</span>
                    </div>`;
                }

                // Generate URL strictly for services that have wildcard *http* in banner/service
                if (!displayUrl && isHttpService && host) {
                    const isHttps = data.ssl || rawType === 'https' || serviceStr.includes('https') || bannerStr.includes('https') || [443, 8443].includes(parseInt(data.port));
                    const scheme = isHttps ? 'https' : 'http';
                    if (data.port) {
                        const portSuffix = ((scheme === 'http' && data.port == 80) || (scheme === 'https' && data.port == 443)) ? '' : `:${data.port}`;
                        displayUrl = `${scheme}://${host}${portSuffix}`;
                    }
                }

                if (isHttpService && displayUrl) {
                    urlHtml = `
                    <div class="property">
                        <span class="key">URL:</span>
                        <span class="value"><a href="${displayUrl}" target="_blank" style="color: #00d4ff; text-decoration: underline; word-break: break-all;">${displayUrl}</a></span>
                    </div>`;
                }
            } catch (err) {
                console.error("Error generating service details HTML:", err);
            }

            const riskMetricsHtml = this.renderRiskMetricsAccordion(data, elements);

            html = `
                <h4>Service Information</h4>
                ${hostHtml}
                <div class="property">
                    <span class="key">Port:</span>
                    <span class="value">${data.port}/${data.protocol}</span>
                </div>
                ${urlHtml}
                <div class="property">
                    <span class="key">Service:</span>
                    <span class="value">${data.service || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">Product:</span>
                    <span class="value">${data.product || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">Version:</span>
                    <span class="value">${data.version || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">SSL/TLS:</span>
                    <span class="value">${data.ssl ? 'Yes' : 'No'}</span>
                </div>
                ${(data.verified_active || data.is_active_scan) ? `
                <div class="property">
                    <span class="key">Verification Status:</span>
                    <span class="value"><span class="badge-verified-active"><i data-lucide="check-circle" style="width: 12px; height: 12px;"></i> Confirmed Active</span></span>
                </div>
                ` : `
                <div class="property">
                    <span class="key">Verification Status:</span>
                    <span class="value"><span class="badge-unverified"><i data-lucide="clock" style="width: 12px; height: 12px;"></i> Passive (Awaiting Active Confirmation)</span></span>
                </div>
                `}
                ${Array.isArray(data.sources) && data.sources.length > 0 ? `
                <div class="property">
                    <span class="key">Sources:</span>
                    <span class="value">${data.sources.join(', ')}</span>
                </div>
                ` : ''}
                ${data.banner ? `
                <div class="property banner-property" style="flex-direction: column; align-items: flex-start; gap: 0.25rem;">
                    <span class="key" style="margin-bottom: 0.2rem;">Banner:</span>
                    <pre class="service-banner-preview" style="background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; padding: 0.5rem 0.65rem; font-family: var(--font-mono, monospace); font-size: 0.76rem; color: #38bdf8; white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow-y: auto; width: 100%; margin: 0;">${this.escapeHtml(data.banner)}</pre>
                </div>
                ` : ''}
                ${riskMetricsHtml}
            `;
        } else if (rawType === 'vulnerability') {
            const kevBadge = data.is_cisa_kev === true ? '<span class="vulnerability-badge kev">CISA KEV</span>' : '';
            const severityClass = (data.severity || 'unknown').toLowerCase();
            
            // Resolve connected service(s), host IP(s), and associated domain(s)
            const associatedServices = [];
            const associatedHosts = [];
            const associatedDomains = new Set();

            if (elements && Array.isArray(elements.edges) && Array.isArray(elements.nodes)) {
                // Find all incoming HAS_VULN edges connected to this vulnerability node
                const vulnEdges = elements.edges.filter(e => e && e.data && e.data.target === data.id && e.data.label === 'HAS_VULN');
                
                vulnEdges.forEach(vulnEdge => {
                    const sourceNode = elements.nodes.find(n => n && n.data && n.data.id === vulnEdge.data.source);
                    if (sourceNode && sourceNode.data) {
                        if (['service', 'http', 'https'].includes(sourceNode.data.type)) {
                            const sData = sourceNode.data;
                            
                            // Find IP exposing this service
                            let srvIp = null;
                            const srvEdge = elements.edges.find(e => e && e.data && e.data.target === sData.id && e.data.label === 'EXPOSES');
                            if (srvEdge) {
                                const ipNode = elements.nodes.find(n => n && n.data && n.data.id === srvEdge.data.source);
                                if (ipNode && ipNode.data) {
                                    srvIp = ipNode.data;
                                    if (!associatedHosts.some(h => h.id === srvIp.id)) {
                                        associatedHosts.push(srvIp);
                                    }
                                }
                            }

                            associatedServices.push({
                                id: sData.id,
                                port: sData.port,
                                protocol: sData.protocol,
                                service: sData.service,
                                product: sData.product,
                                version: sData.version,
                                url: sData.url,
                                ssl: sData.ssl,
                                ip: srvIp ? (srvIp.ip || srvIp.name || srvIp.label) : (sData.ip || ''),
                                ip_id: srvIp ? srvIp.id : (sData.ip_id || null)
                            });
                        } else if (sourceNode.data.type === 'ip') {
                            const ipData = sourceNode.data;
                            if (!associatedHosts.some(h => h.id === ipData.id)) {
                                associatedHosts.push(ipData);
                            }
                        }
                    }
                });

                // Find associated domains / subdomains for all connected hosts
                associatedHosts.forEach(hostData => {
                    const hId = hostData.id;
                    elements.edges.forEach(e => {
                        if (e && e.data) {
                            if (e.data.source === hId && e.data.label === 'HAS_SUBDOMAIN') {
                                const subNode = elements.nodes.find(n => n && n.data && n.data.id === e.data.target);
                                if (subNode && subNode.data) associatedDomains.add(subNode.data.name || subNode.data.label);
                            }
                            if (e.data.target === hId && e.data.label === 'RESOLVES_TO') {
                                const subNode = elements.nodes.find(n => n && n.data && n.data.id === e.data.source);
                                if (subNode && subNode.data) associatedDomains.add(subNode.data.name || subNode.data.label);
                            }
                        }
                    });
                });
            }

            // Build Host & Service Section HTML
            let hostAndServiceHtml = '';
            const domainsList = Array.from(associatedDomains);
            const domainBadgeHtml = domainsList.length > 0 
                ? domainsList.map(d => `<span class="mini-badge" style="background: rgba(0,212,255,0.15); color: #00d4ff; font-family: monospace;">${d}</span>`).join(' ')
                : '';

            let hostsListHtml = '';
            if (associatedHosts.length > 0) {
                hostsListHtml = associatedHosts.map(h => {
                    const hIp = h.ip || h.name || h.label || 'Unknown IP';
                    const hOrg = [h.org, h.country ? `[${h.country}]` : '', h.asn ? `(${h.asn})` : ''].filter(Boolean).join(' ');
                    return `
                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 4px 8px; margin-bottom: 4px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 4px;">
                        <div>
                            <span style="color: #00d4ff; font-weight: bold; font-family: monospace;">${hIp}</span>
                            ${hOrg ? `<span style="color: #94a3b8; font-size: 0.78rem; margin-left: 6px;">${hOrg}</span>` : ''}
                        </div>
                        <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem;" onclick="window.dashboard.focusNode('${h.id}')"><i data-lucide="focus" class="badge-icon"></i> Focus</button>
                    </div>`;
                }).join('');
            } else if (data.ip) {
                hostsListHtml = `
                <div class="property">
                    <span class="key">Host / IP Address:</span>
                    <span class="value" style="color: #00d4ff; font-weight: bold;">${data.ip}</span>
                </div>`;
            }

            let servicesListHtml = '';
            if (associatedServices.length > 0) {
                servicesListHtml = associatedServices.map(s => {
                    const sPort = s.port ? `${s.port}/${(s.protocol || 'tcp').toUpperCase()}` : 'Port N/A';
                    const sDesc = [s.service, s.product, s.version ? `v${s.version}` : ''].filter(Boolean).join(' - ') || 'Unknown';
                    return `
                    <div style="display: flex; align-items: center; justify-content: space-between; padding: 4px 8px; margin-bottom: 4px; background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 4px;">
                        <div>
                            <span style="color: #ffa502; font-weight: bold; font-family: monospace;">${sPort}</span>
                            <span style="color: #cbd5e1; font-size: 0.82rem; margin-left: 6px;">${sDesc}</span>
                            ${s.ip ? `<span style="color: #64748b; font-size: 0.75rem; margin-left: 4px;">(${s.ip})</span>` : ''}
                        </div>
                        <button type="button" class="risk-focus-btn" style="margin: 0; padding: 2px 6px; font-size: 0.72rem;" onclick="window.dashboard.focusNode('${s.id}')"><i data-lucide="focus" class="badge-icon"></i> Focus</button>
                    </div>`;
                }).join('');
            } else if (data.port) {
                servicesListHtml = `
                <div class="property">
                    <span class="key">Affected Port / Protocol:</span>
                    <span class="value" style="color: #ffa502; font-weight: bold;">${data.port}/${(data.protocol || 'tcp').toUpperCase()}</span>
                </div>`;
            }

            hostAndServiceHtml = `
                <h4 style="margin-top: 15px; margin-bottom: 10px; border-bottom: 1px solid #333; padding-bottom: 5px; color: #00d4ff;">Affected Targets & Services</h4>
                
                ${hostsListHtml ? `
                <div style="margin-bottom: 8px;">
                    <span class="key" style="display: block; margin-bottom: 4px; font-weight: 500;">Affected Host(s):</span>
                    ${hostsListHtml}
                </div>` : ''}

                ${servicesListHtml ? `
                <div style="margin-bottom: 8px;">
                    <span class="key" style="display: block; margin-bottom: 4px; font-weight: 500;">Affected Service(s):</span>
                    ${servicesListHtml}
                </div>` : ''}

                ${domainBadgeHtml ? `
                <div class="property" style="flex-direction: column; align-items: flex-start; gap: 4px; margin-top: 6px;">
                    <span class="key">Associated Domain(s):</span>
                    <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 2px;">${domainBadgeHtml}</div>
                </div>` : ''}
            `;
            
            // Build exploits/PoCs section with GitHub and ExploitDB separation
            let exploitsSection = '';
            if (data.exploits && data.exploits.length > 0) {
                const githubExploits = data.exploits.filter(e => String(e.source || "").toLowerCase().includes('github'));
                const exploitdbExploits = data.exploits.filter(e => !String(e.source || "").toLowerCase().includes('github'));
                
                exploitsSection = '<h4>Available Exploits & PoCs</h4>';
                
                if (githubExploits.length > 0) {
                    exploitsSection += '<h5 style="color: #00d4ff; margin: 1rem 0 0.5rem 0;"><i data-lucide="github" class="badge-icon"></i> GitHub PoCs</h5>';
                    githubExploits.forEach(exploit => {
                        const verifiedBadge = exploit.verified ? '<span class="exploit-badge verified">Verified</span>' : '';
                        
                        exploitsSection += `
                        <div class="exploit-item">
                            <div class="exploit-header">
                                <span class="exploit-source github">${exploit.source}</span>
                                ${verifiedBadge}
                            </div>
                            <div class="exploit-title">${exploit.title}</div>
                            <div class="exploit-details">
                                ${exploit.author ? `<span>Author: ${exploit.author}</span>` : ''}
                                ${exploit.date ? `<span>Date: ${exploit.date}</span>` : ''}
                                ${exploit.exploit_type ? `<span>Type: ${exploit.exploit_type}</span>` : ''}
                            </div>
                            <div class="exploit-url">
                                <a href="${exploit.url}" target="_blank" rel="noopener"><i data-lucide="external-link" class="badge-icon"></i> ${exploit.url}</a>
                            </div>
                        </div>`;
                    });
                }
                
                if (exploitdbExploits.length > 0) {
                    exploitsSection += '<h5 style="color: #e74c3c; margin: 1rem 0 0.5rem 0;"><i data-lucide="file-code" class="badge-icon"></i> ExploitDB</h5>';
                    exploitdbExploits.forEach(exploit => {
                        const verifiedBadge = exploit.verified ? '<span class="exploit-badge verified">Verified</span>' : '';
                        
                        exploitsSection += `
                        <div class="exploit-item">
                            <div class="exploit-header">
                                <span class="exploit-source exploitdb">${exploit.source}</span>
                                ${verifiedBadge}
                            </div>
                            <div class="exploit-title">${exploit.title}</div>
                            <div class="exploit-details">
                                ${exploit.author ? `<span>Author: ${exploit.author}</span>` : ''}
                                ${exploit.date ? `<span>Date: ${exploit.date}</span>` : ''}
                                ${exploit.exploit_type ? `<span>Type: ${exploit.exploit_type}</span>` : ''}
                            </div>
                            <div class="exploit-url">
                                <a href="${exploit.url}" target="_blank" rel="noopener"><i data-lucide="external-link" class="badge-icon"></i> ${exploit.url}</a>
                            </div>
                        </div>`;
                    });
                }
            }
            
            html = `
                <h4>Vulnerability Details</h4>
                <div class="property">
                    <span class="key">CVE ID:</span>
                    <span class="value" style="color: #00d4ff; font-weight: bold;">${data.cve_id}</span>
                </div>
                <div class="property">
                    <span class="key">Severity:</span>
                    <span class="value">
                        <span class="vulnerability-badge ${severityClass}">${data.severity}</span>
                        ${kevBadge}
                    </span>
                </div>
                <div class="property">
                    <span class="key">CVSS Score:</span>
                    <span class="value">${data.cvss_score || 'N/A'}</span>
                </div>
                <div class="property">
                    <span class="key">EPSS Score:</span>
                    <span class="value">${data.epss_score ? (data.epss_score * 100).toFixed(1) + '%' : 'N/A'}</span>
                </div>
                <div class="property">
                    <span class="key">Source:</span>
                    <span class="value">
                        <span class="mini-badge" style="background: rgba(0, 240, 255, 0.12); color: #00f0ff; border: 1px solid rgba(0, 240, 255, 0.3); font-weight: 600; padding: 2px 8px; border-radius: 4px;">
                            ${data.source || 'NVD'}
                        </span>
                    </span>
                </div>
                <div class="property">
                    <span class="key">Risk Level:</span>
                    <span class="value">${data.risk_level || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">Available PoCs:</span>
                    <span class="value">${data.exploit_count || 0}</span>
                </div>
                ${hostAndServiceHtml}
                ${data.description ? `
                <h4>Description</h4>
                <p style="font-size: 0.85rem; line-height: 1.4; color: #ccc; background: #181818; padding: 8px; border-radius: 4px; border: 1px solid #2a2a2a;">${data.description}</p>
                ` : ''}
                ${exploitsSection}
            `;
        } else {
            // Generic Fallback for any other node types
            const riskMetricsHtml = this.renderRiskMetricsAccordion(data, elements);
            html = `
                <h4>Asset Details</h4>
                <div class="property">
                    <span class="key">Label:</span>
                    <span class="value">${data.label || data.name || data.id || 'N/A'}</span>
                </div>
                <div class="property">
                    <span class="key">Type:</span>
                    <span class="value">${(data.type || 'Unknown').toUpperCase()}</span>
                </div>
                ${riskMetricsHtml}
            `;
        }

        content.innerHTML = html;

        drawer.classList.add('open');
        const inspectorBackdrop = document.getElementById('inspector-backdrop');
        if (inspectorBackdrop && window.innerWidth <= 992) {
            inspectorBackdrop.classList.add('active');
        }

        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }

        // Defer resize slightly so Cytoscape finishes processing tap/mouseup lifecycle without freezing drag state
        setTimeout(() => {
            if (this.cy) {
                this.cy.resize();
            }
        }, 50);
        } catch (err) {
            console.error('[EASMDashboard] Error rendering node inspector:', err);
            const drawer = document.getElementById('inspector-drawer');
            const content = document.getElementById('inspector-content');
            if (content) {
                content.innerHTML = `<div style="color: #ef4444; padding: 15px;"><h4>Error Rendering Inspector</h4><pre style="white-space: pre-wrap; font-size: 0.75rem;">${err.stack || err.message || String(err)}</pre></div>`;
            }
            if (drawer) drawer.classList.add('open');
        }
    }

    toggleClusterExpansion(clusterId) {
        let isExpanding = false;
        let parentId = null;

        const clusterNode = this.cy.getElementById(clusterId);
        if (clusterNode.length > 0) {
            parentId = clusterNode.data('parent_ip') || clusterNode.data('parent_srv');
        }

        if (this.expandedClusters.has(clusterId)) {
            this.expandedClusters.delete(clusterId);
            this.manualCollapsedClusters.add(clusterId);
            isExpanding = false;
        } else {
            this.expandedClusters.add(clusterId);
            this.manualCollapsedClusters.delete(clusterId);
            isExpanding = true;
        }
        this.closeInspector();
        
        if (isExpanding && parentId) {
            this.applyLeadFilter({ expandedClusterId: clusterId, parentId: parentId });
        } else {
            this.applyLeadFilter({ relayout: false });
        }
    }

    toggleAssetChildrenCollapse(assetId, type) {
        let prefix = 'cluster_srv_';
        if (type === 'ip_vulns') {
            prefix = 'cluster_ip_vuln_';
        } else if (type === 'vulns') {
            prefix = 'cluster_vuln_';
        }
        const clusterId = `${prefix}${assetId}`;

        const existingCluster = this.cy.getElementById(clusterId);
        const isCurrentlyCollapsed = existingCluster.length > 0 && !existingCluster.hidden();

        if (isCurrentlyCollapsed) {
            // Uncollapse: open and spread children
            this.manualCollapsedClusters.delete(clusterId);
            this.expandedClusters.add(clusterId);
            this.closeInspector();
            this.applyLeadFilter({ expandedClusterId: clusterId, parentId: assetId });
        } else {
            // Collapse: group children into cluster node
            this.expandedClusters.delete(clusterId);
            this.manualCollapsedClusters.add(clusterId);
            this.closeInspector();
            this.applyLeadFilter({ relayout: false });
        }
    }

    showCoreContextMenu(x, y) {
        const menu = document.getElementById('cy-context-menu');
        if (!menu) return;

        // Build HTML for core context menu
        menu.innerHTML = `
            <div class="cy-context-menu-header" style="justify-content: center; background: rgba(15, 23, 42, 0.95); border-bottom: 1px solid rgba(255,255,255,0.05); border-radius: 6px 6px 0 0; padding: 10px;">
                <span class="node-title" style="font-size: 0.8rem; color: #94a3b8; font-weight: 500; letter-spacing: 0.5px;">CANVAS MENU</span>
            </div>
            
            <button type="button" class="cy-context-menu-item ctx-collapse-btn" data-action-id="ctx-action-explore-leads">
                <i data-lucide="compass" class="ui-icon" style="color: #60a5fa;"></i>
                <span style="color: #f8fafc; font-weight: 500;">Explore Leads...</span>
            </button>
            
            <div class="cy-context-menu-divider"></div>

            <button type="button" class="cy-context-menu-item ctx-collapse-btn" data-action-id="ctx-action-expand-all">
                <i data-lucide="layers" class="ui-icon" style="color: #4ecdc4;"></i>
                <span style="color: #f8fafc;">Target All Leads</span>
            </button>

            <button type="button" class="cy-context-menu-item ctx-collapse-btn" data-action-id="ctx-action-fit-graph">
                <i data-lucide="maximize" class="ui-icon" style="color: #a78bfa;"></i>
                <span style="color: #f8fafc;">Fit Graph to Screen</span>
            </button>
        `;

        // Wire actions
        menu.querySelectorAll('.ctx-collapse-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.hideContextMenu();
                
                const actId = btn.getAttribute('data-action-id');
                if (actId === 'ctx-action-explore-leads') {
                    const modal = document.getElementById('floating-leads-modal');
                    if (modal) modal.style.display = 'flex';
                } else if (actId === 'ctx-action-expand-all') {
                    this.selectAllLeads();
                } else if (actId === 'ctx-action-fit-graph') {
                    if (this.cy) this.cy.fit(null, 50);
                }
            });
        });

        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }

        // Adjust position
        menu.style.display = 'flex';
        menu.style.visibility = 'hidden';

        requestAnimationFrame(() => {
            const menuRect = menu.getBoundingClientRect();
            const maxX = window.innerWidth - menuRect.width - 12;
            const maxY = window.innerHeight - menuRect.height - 12;

            const posX = Math.max(10, Math.min(x, maxX));
            const posY = Math.max(10, Math.min(y, maxY));

            menu.style.left = `${posX}px`;
            menu.style.top = `${posY}px`;
            menu.style.visibility = 'visible';
        });

        this.contextMenuVisible = true;
    }

    showContextMenu(node, x, y) {
        const menu = document.getElementById('cy-context-menu');
        if (!menu) return;

        const data = node.data();
        const nodeType = data.type;
        const nodeId = data.id;
        const elements = this.graphData?.elements || (window.dashboard && window.dashboard.graphData?.elements);

        // 1. Determine Collapse / Uncollapse actions (100% in English)
        const collapseActions = [];

        if (nodeId === 'target_root') {
            collapseActions.push({
                id: 'ctx-action-explore-leads',
                label: 'Explore Leads...',
                icon: 'compass',
                disabled: false,
                action: () => {
                    const modal = document.getElementById('floating-leads-modal');
                    if (modal) {
                        modal.style.display = 'flex';
                        this.hideContextMenu();
                    }
                }
            });
            collapseActions.push({
                id: 'ctx-action-expand-all',
                label: 'Target All Leads',
                icon: 'layers',
                disabled: false,
                action: () => {
                    this.selectAllLeads();
                    this.hideContextMenu();
                }
            });
        }

        if (data.is_cluster || nodeType === 'cluster_services' || nodeType === 'cluster_vulns') {
            const isServiceCluster = nodeType === 'cluster_services';
            collapseActions.push({
                id: 'ctx-action-cluster',
                label: isServiceCluster ? `Uncollapse Services (${data.count})` : `Uncollapse Vulnerabilities (${data.count})`,
                icon: 'maximize-2',
                disabled: false,
                action: () => {
                    this.toggleClusterExpansion(nodeId);
                }
            });
        } else if (nodeType === 'ip') {
            const clusterSrv = this.cy.getElementById(`cluster_srv_${nodeId}`);
            const isServicesCollapsed = clusterSrv.length > 0 && !clusterSrv.hidden();
            let servicesCount = isServicesCollapsed ? (clusterSrv.data('count') || 0) : node.outgoers('node[type="service"], node[type="http"], node[type="https"]').filter(s => !s.hidden()).length;
            if (servicesCount === 0 && isServicesCollapsed) servicesCount = clusterSrv.data('count') || 0;

            const clusterVuln = this.cy.getElementById(`cluster_ip_vuln_${nodeId}`);
            const isVulnsCollapsed = clusterVuln.length > 0 && !clusterVuln.hidden();
            let directVulnsCount = isVulnsCollapsed ? (clusterVuln.data('count') || 0) : node.outgoers('node[type="vulnerability"]').filter(v => !v.hidden()).length;
            if (directVulnsCount === 0 && isVulnsCollapsed) directVulnsCount = clusterVuln.data('count') || 0;

            if (servicesCount > 1 || isServicesCollapsed) {
                collapseActions.push({
                    id: 'ctx-action-collapse-srv',
                    label: isServicesCollapsed ? `Uncollapse Services (${servicesCount})` : `Collapse Services (${servicesCount})`,
                    icon: isServicesCollapsed ? 'maximize-2' : 'minimize-2',
                    disabled: false,
                    action: () => {
                        this.toggleAssetChildrenCollapse(nodeId, 'services');
                    }
                });
            }

            if (directVulnsCount > 1 || isVulnsCollapsed) {
                collapseActions.push({
                    id: 'ctx-action-collapse-vuln',
                    label: isVulnsCollapsed ? `Uncollapse Direct Vulnerabilities (${directVulnsCount})` : `Collapse Direct Vulnerabilities (${directVulnsCount})`,
                    icon: isVulnsCollapsed ? 'maximize-2' : 'minimize-2',
                    disabled: false,
                    action: () => {
                        this.toggleAssetChildrenCollapse(nodeId, 'ip_vulns');
                    }
                });
            }

            if (collapseActions.length === 0) {
                collapseActions.push({
                    id: 'ctx-action-collapse-none',
                    label: 'Collapse / Uncollapse (Not enough children)',
                    icon: 'minimize-2',
                    disabled: true,
                    action: () => {}
                });
            }
        } else if (nodeType === 'service' || nodeType === 'http' || nodeType === 'https') {
            const clusterVuln = this.cy.getElementById(`cluster_vuln_${nodeId}`);
            const isVulnsCollapsed = clusterVuln.length > 0 && !clusterVuln.hidden();
            let vulnsCount = isVulnsCollapsed ? (clusterVuln.data('count') || 0) : node.outgoers('node[type="vulnerability"]').filter(v => !v.hidden()).length;
            if (vulnsCount === 0 && isVulnsCollapsed) vulnsCount = clusterVuln.data('count') || 0;

            if (vulnsCount > 1 || isVulnsCollapsed) {
                collapseActions.push({
                    id: 'ctx-action-collapse-srv-vuln',
                    label: isVulnsCollapsed ? `Uncollapse Vulnerabilities (${vulnsCount})` : `Collapse Vulnerabilities (${vulnsCount})`,
                    icon: isVulnsCollapsed ? 'maximize-2' : 'minimize-2',
                    disabled: false,
                    action: () => {
                        this.toggleAssetChildrenCollapse(nodeId, 'vulns');
                    }
                });
            } else {
                collapseActions.push({
                    id: 'ctx-action-collapse-none',
                    label: 'Collapse / Uncollapse (Not enough vulnerabilities)',
                    icon: 'minimize-2',
                    disabled: true,
                    action: () => {}
                });
            }
        } else {
            collapseActions.push({
                id: 'ctx-action-collapse-none',
                label: 'Collapse / Uncollapse (Not applicable)',
                icon: 'minimize-2',
                disabled: true,
                action: () => {}
            });
        }

        // 2. Determine Copy Action (Available ONLY for domain, subdomain, ip, and vulnerability/cve)
        let copyAction = null;
        if (nodeType === 'domain') {
            const textToCopy = data.name || data.label || nodeId;
            copyAction = {
                label: 'Copy Domain',
                text: textToCopy
            };
        } else if (nodeType === 'subdomain') {
            const textToCopy = data.name || data.label || nodeId;
            copyAction = {
                label: 'Copy Subdomain',
                text: textToCopy
            };
        } else if (nodeType === 'ip') {
            const textToCopy = data.ip || data.name || data.label || nodeId;
            copyAction = {
                label: 'Copy IP Address',
                text: textToCopy
            };
        } else if (nodeType === 'vulnerability' || nodeType === 'cve') {
            const textToCopy = data.cve_id || data.name || data.label || nodeId;
            copyAction = {
                label: 'Copy CVE ID',
                text: textToCopy
            };
        }

        const displayName = data.label || data.name || data.ip || data.cve_id || nodeId;

        // 3. Target Management Action for IP Nodes and FQDN (Domain/Subdomain/Target) Nodes
        let targetBtnHtml = '';
        let targetValue = null;
        let rootAssociatedIps = [];

        const isRootTarget = nodeType === 'target' || nodeId === 'target_root' || data.is_root === true;
        const isFqdnNode = ['domain', 'subdomain'].includes(nodeType) && !isRootTarget;
        if (nodeType === 'ip') {
            targetValue = String(data.ip || data.name || data.label || nodeId).replace(/^ip_/, '').trim();
            const isMarked = this.isTargetMarked(targetValue);
            targetBtnHtml = `
                <button type="button" class="cy-context-menu-item" id="ctx-action-target" style="color: ${isMarked ? '#ef4444' : '#00f0ff'};">
                    <i data-lucide="crosshair" class="ui-icon" style="color: ${isMarked ? '#ef4444' : '#00f0ff'};"></i>
                    <span>${isMarked ? 'Remove Target' : 'Set as Target'}</span>
                </button>
            `;
        } else if (isFqdnNode) {
            targetValue = String(data.name || data.label || nodeId).replace(/^(dom_|sub_|target_)/, '').trim();
            if (targetValue) {
                const isMarked = this.isTargetMarked(targetValue);
                targetBtnHtml = `
                    <button type="button" class="cy-context-menu-item" id="ctx-action-target" style="color: ${isMarked ? '#ef4444' : '#00f0ff'};">
                        <i data-lucide="crosshair" class="ui-icon" style="color: ${isMarked ? '#ef4444' : '#00f0ff'};"></i>
                        <span>${isMarked ? `Remove ${targetValue} from Targets` : `Set as Target (FQDN)`}</span>
                    </button>
                `;
            }
        }

        rootAssociatedIps = this.getAssociatedIpNodes(node);
        if (rootAssociatedIps.length > 0) {
            const totalCount = rootAssociatedIps.length;
            const markedCount = rootAssociatedIps.filter(ipN => {
                const rawIp = ipN.data('ip') || ipN.data('label') || ipN.data('name') || ipN.id();
                return this.isTargetMarked(rawIp);
            }).length;
            const allMarked = markedCount === totalCount;
            targetBtnHtml += `
                <button type="button" class="cy-context-menu-item" id="ctx-action-root-target" style="color: ${allMarked ? '#ef4444' : '#00f0ff'};">
                    <i data-lucide="layers" class="ui-icon" style="color: ${allMarked ? '#ef4444' : '#00f0ff'};"></i>
                    <span>${allMarked ? `Remove all ${totalCount} IPs from Targets` : `Set all ${totalCount} resolved IPs as Targets (${markedCount}/${totalCount})`}</span>
                </button>
            `;
        }

        // 4. Unverify Active Status Action (Single service node with Verified Active or Root/Parent with associated active services)
        let unverifyBtnHtml = '';
        let verifiedServicesToReset = [];

        if (['service', 'http', 'https'].includes(nodeType)) {
            const isVerified = data.verified_active === true || data.is_active_scan === true || 
                (Array.isArray(data.sources) && data.sources.some(s => String(s).toLowerCase().includes('masscan') || String(s).toLowerCase().includes('active')));
            if (isVerified) {
                verifiedServicesToReset = [node];
                unverifyBtnHtml = `
                    <button type="button" class="cy-context-menu-item" id="ctx-action-unverify-service" style="color: #f59e0b;">
                        <i data-lucide="shield-off" class="ui-icon" style="color: #f59e0b;"></i>
                        <span>Remove Verified Active</span>
                    </button>
                `;
            }
        } else {
            const allAssociatedServices = this.getAssociatedServiceNodes(node);
            verifiedServicesToReset = allAssociatedServices.filter(sNode => {
                const sData = sNode.data();
                return sData.verified_active === true || sData.is_active_scan === true || 
                    (Array.isArray(sData.sources) && sData.sources.some(s => String(s).toLowerCase().includes('masscan') || String(s).toLowerCase().includes('active')));
            });

            if (verifiedServicesToReset.length > 0) {
                const vCount = verifiedServicesToReset.length;
                unverifyBtnHtml = `
                    <button type="button" class="cy-context-menu-item" id="ctx-action-unverify-all-services" style="color: #f59e0b;">
                        <i data-lucide="shield-off" class="ui-icon" style="color: #f59e0b;"></i>
                        <span>Remove Verified Active (${vCount} Service${vCount > 1 ? 's' : ''})</span>
                    </button>
                `;
            }
        }

        const collapseButtonsHtml = collapseActions.map(act => `
            <button type="button" class="cy-context-menu-item primary ctx-collapse-btn" data-action-id="${act.id}" ${act.disabled ? 'disabled' : ''}>
                <i data-lucide="${act.icon}" class="ui-icon"></i>
                <span>${act.label}</span>
            </button>
        `).join('');

        menu.innerHTML = `
            <div class="cy-context-menu-header">
                <span>${nodeType.toUpperCase()}</span>
                <span class="node-title" title="${displayName}">${displayName}</span>
            </div>
            ${collapseButtonsHtml}
            <div class="cy-context-menu-divider"></div>
            ${targetBtnHtml}
            ${unverifyBtnHtml}
            <button type="button" class="cy-context-menu-item" id="ctx-action-inspect">
                <i data-lucide="info" class="ui-icon"></i>
                <span>Inspect Details</span>
            </button>
            <button type="button" class="cy-context-menu-item" id="ctx-action-focus">
                <i data-lucide="crosshair" class="ui-icon"></i>
                <span>Focus Node</span>
            </button>
            ${copyAction ? `
            <button type="button" class="cy-context-menu-item" id="ctx-action-copy">
                <i data-lucide="copy" class="ui-icon"></i>
                <span>${copyAction.label}</span>
            </button>
            ` : ''}
        `;

        // Wire collapse button actions
        menu.querySelectorAll('.ctx-collapse-btn').forEach(btn => {
            const actId = btn.getAttribute('data-action-id');
            const matchedAction = collapseActions.find(a => a.id === actId);
            if (matchedAction && !matchedAction.disabled) {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.hideContextMenu();
                    matchedAction.action();
                });
            }
        });

        // Wire target button action (IP or FQDN)
        const targetBtn = menu.querySelector('#ctx-action-target');
        if (targetBtn && targetValue) {
            targetBtn.addEventListener('click', async (e) => {
                e.stopPropagation();
                this.hideContextMenu();
                await this.toggleTargetMark(targetValue, node);
            });
        }

        // Wire root / org / domain target button action for all associated IPs
        const rootTargetBtn = menu.querySelector('#ctx-action-root-target');
        if (rootTargetBtn && rootAssociatedIps.length > 0) {
            rootTargetBtn.addEventListener('click', async (e) => {
                e.stopPropagation();
                this.hideContextMenu();
                const ipStrings = rootAssociatedIps.map(ipN => {
                    const rawIp = ipN.data('ip') || ipN.data('label') || ipN.data('name') || ipN.id();
                    return String(rawIp || '').replace(/^ip_/, '').trim();
                }).filter(Boolean);

                const markedCount = ipStrings.filter(ip => this.isTargetMarked(ip)).length;
                if (markedCount === ipStrings.length) {
                    await this.removeTargetsBulk(ipStrings);
                } else {
                    await this.setTargetsBulk(ipStrings, rootAssociatedIps);
                }
            });
        }

        // Wire unverify action for single service node or root / parent nodes
        const unverifyServiceBtn = menu.querySelector('#ctx-action-unverify-service');
        if (unverifyServiceBtn && verifiedServicesToReset.length === 1) {
            unverifyServiceBtn.addEventListener('click', async (e) => {
                e.stopPropagation();
                this.hideContextMenu();
                await this.unverifyServices(verifiedServicesToReset);
            });
        }

        const unverifyAllBtn = menu.querySelector('#ctx-action-unverify-all-services');
        if (unverifyAllBtn && verifiedServicesToReset.length > 0) {
            unverifyAllBtn.addEventListener('click', async (e) => {
                e.stopPropagation();
                this.hideContextMenu();
                await this.unverifyServices(verifiedServicesToReset);
            });
        }

        const inspectBtn = menu.querySelector('#ctx-action-inspect');
        if (inspectBtn) {
            inspectBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.hideContextMenu();
                this.showNodeInspector(node);
            });
        }

        const focusBtn = menu.querySelector('#ctx-action-focus');
        if (focusBtn) {
            focusBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.hideContextMenu();
                this.focusNode(nodeId);
            });
        }

        if (copyAction) {
            const copyBtn = menu.querySelector('#ctx-action-copy');
            if (copyBtn) {
                copyBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.hideContextMenu();
                    this.copyTextList(copyAction.text, copyBtn);
                });
            }
        }

        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }

        // Adjust position so it doesn't overflow window boundaries
        menu.style.display = 'flex';
        menu.style.visibility = 'hidden';

        requestAnimationFrame(() => {
            const menuRect = menu.getBoundingClientRect();
            const maxX = window.innerWidth - menuRect.width - 12;
            const maxY = window.innerHeight - menuRect.height - 12;

            const posX = Math.max(10, Math.min(x, maxX));
            const posY = Math.max(10, Math.min(y, maxY));

            menu.style.left = `${posX}px`;
            menu.style.top = `${posY}px`;
            menu.style.visibility = 'visible';
        });
    }

    hideContextMenu() {
        const menu = document.getElementById('cy-context-menu');
        if (menu) {
            menu.style.display = 'none';
        }
    }

    closeInspector() {
        const drawer = document.getElementById('inspector-drawer');
        if (drawer) drawer.classList.remove('open');
        const inspectorBackdrop = document.getElementById('inspector-backdrop');
        if (inspectorBackdrop) inspectorBackdrop.classList.remove('active');
        if (this.cy) {
            this.cy.nodes().unselect();
            this.cy.resize();
        }
    }

    showError(message) {
        console.error('Dashboard error:', message);
        const loading = document.getElementById('graph-loading');
        if (loading) {
            loading.innerHTML = `
                <div style="color: #ff4757; text-align: center;">
                    <h3><i data-lucide="alert-triangle" class="ui-icon" style="width: 20px; height: 20px; vertical-align: middle;"></i> Error</h3>
                    <p>${message}</p>
                    <p style="font-size: 0.9em; color: #aaa;">Check browser console for details</p>
                    <button onclick="location.reload()" style="margin-top: 15px; padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">
                        Reload Dashboard
                    </button>
                </div>
            `;
            loading.style.display = 'flex';
            if (typeof lucide !== 'undefined') lucide.createIcons();
        }
    }

    showEmergencyLeadSelector() {
        console.log('Showing emergency lead selector fallback...');
        const leadList = document.getElementById('lead-list');
        if (leadList) {
            leadList.innerHTML = `
                <div class="lead-loading" style="color: #ff9500;">
                    <i data-lucide="alert-circle" class="ui-icon" style="width: 16px; height: 16px; vertical-align: middle;"></i> API Connection Failed<br>
                    <small>Unable to load leads from database</small><br>
                    <button onclick="location.reload()" 
                            style="margin-top: 10px; padding: 5px 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer;">
                        Retry Connection
                    </button>
                </div>
            `;
            if (typeof lucide !== 'undefined') lucide.createIcons();
        }
    }

    forcePopulateFromCytoscape() {
        console.log('🚨 FORCE POPULATE: Attempting to extract leads directly from Cytoscape...');
        
        if (!this.cy) {
            console.error('Cytoscape not initialized, cannot force populate');
            return;
        }
        
        try {
            const allNodes = this.cy.nodes();
            console.log(`Found ${allNodes.length} nodes in Cytoscape`);
            
            if (allNodes.length === 0) {
                console.error('No nodes in Cytoscape to populate from');
                return;
            }
            
            this.leads = [];
            
            allNodes.forEach((node, index) => {
                try {
                    const nodeData = node.data();
                    console.log(`Force processing node ${index + 1}: ${nodeData.id} (${nodeData.type})`);
                    
                    let displayName = nodeData.label || nodeData.name || nodeData.ip || nodeData.id;
                    if (nodeData.ip) {
                        displayName = nodeData.ip;
                    } else if (nodeData.label && nodeData.label.includes('\n')) {
                        displayName = nodeData.label.split('\n')[0];
                    }
                    
                    const lead = {
                        id: nodeData.id,
                        type: nodeData.type || 'unknown',
                        name: nodeData.name || nodeData.ip || nodeData.label || nodeData.id,
                        display_name: displayName,
                        org: nodeData.org || 'Unknown',
                        country: nodeData.country || 'Unknown',
                        service_count: 0,
                        vuln_count: 0,
                        has_kev: false,
                        has_critical: false,
                        poc_count: 0,
                        ip_count: 0
                    };
                    
                    this.leads.push(lead);
                    console.log(`✓ Force lead created: ${lead.display_name}`);
                } catch (error) {
                    console.error(`Error force processing node ${index}:`, error);
                }
            });
            
            console.log(`🚨 FORCE POPULATE: Created ${this.leads.length} leads`);
            this.renderLeadSelector();
            
        } catch (error) {
            console.error('Error in forcePopulateFromCytoscape:', error);
        }
    }

    // =========================================================================
    // Target Management & Active Scan (Masscan) Implementation
    // =========================================================================

    normalizeTargetId(target) {
        if (!target) return target;
        const targetStr = String(target).trim();
        const targetLower = targetStr.toLowerCase();
        
        // Ensure we always return the string (IP or FQDN), never the database ID.
        // The backend active scanners (masscan/nuclei) need the actual address, not an internal ID.
        if (this.leads && Array.isArray(this.leads)) {
            const matchingLead = this.leads.find(l => {
                const lName = (l.name || l.display_name || l.label || '').toLowerCase();
                const lId = (l.id || '').toLowerCase();
                return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
            });
            
            if (matchingLead) {
                return matchingLead.display_name || matchingLead.label || matchingLead.name || targetStr;
            }
        }
        return targetStr.replace(/^(ip_|dom_|sub_|target_)/, '');
    }

    isTargetMarked(ip) {
        if (!ip) return false;
        const normalizedId = this.normalizeTargetId(ip);
        return this.markedTargets.has(normalizedId) || this.markedTargets.has(String(ip).trim());
    }

    async toggleTargetMark(ip, node = null) {
        if (!ip) return;
        ip = ip.trim();
        if (this.isTargetMarked(ip)) {
            await this.removeTarget(ip, node);
        } else {
            await this.setTarget(ip, node);
        }
    }

    filterIpFqdnList(query) {
        const q = String(query || '').trim().toLowerCase();
        const container = document.getElementById('ip-fqdn-list-container');
        if (!container) return;
        const items = container.querySelectorAll('.ip-fqdn-item');
        items.forEach(item => {
            const fqdn = item.getAttribute('data-fqdn') || '';
            item.style.display = (!q || fqdn.includes(q)) ? 'flex' : 'none';
        });
    }

    filterRootDomains(query) {
        const q = String(query || '').trim().toLowerCase();
        const container = document.getElementById('root-domains-list-container');
        if (!container) return;
        const items = container.querySelectorAll('.root-domain-item');
        items.forEach(item => {
            const dom = item.getAttribute('data-domain') || '';
            item.style.display = (!q || dom.includes(q)) ? 'flex' : 'none';
        });
    }

    filterRootSubdomains(query) {
        const q = String(query || '').trim().toLowerCase();
        const container = document.getElementById('root-subdomains-list-container');
        if (!container) return;
        const items = container.querySelectorAll('.root-subdomain-item');
        items.forEach(item => {
            const sub = item.getAttribute('data-subdomain') || '';
            item.style.display = (!q || sub.includes(q)) ? 'flex' : 'none';
        });
    }

    filterRootIps(query) {
        const q = String(query || '').trim().toLowerCase();
        const container = document.getElementById('root-ips-list-container');
        if (!container) return;
        const items = container.querySelectorAll('.root-ip-item');
        items.forEach(item => {
            const ip = item.getAttribute('data-ip') || '';
            const org = item.getAttribute('data-org') || '';
            item.style.display = (!q || ip.includes(q) || org.includes(q)) ? 'flex' : 'none';
        });
    }

    filterDomainSubdomains(query) {
        const q = String(query || '').trim().toLowerCase();
        const container = document.getElementById('domain-subdomains-list-container');
        if (!container) return;
        const items = container.querySelectorAll('.domain-subdomain-item');
        items.forEach(item => {
            const sub = item.getAttribute('data-subdomain') || '';
            item.style.display = (!q || sub.includes(q)) ? 'flex' : 'none';
        });
    }

    async copyFqdnsList(ipNodeId, buttonEl = null) {
        let fqdns = [];
        if (this.cy) {
            const node = this.cy.getElementById(ipNodeId);
            if (node.length > 0 && Array.isArray(node.data('fqdns'))) {
                fqdns = node.data('fqdns');
            }
        }
        if (fqdns.length === 0) {
            const container = document.getElementById('ip-fqdn-list-container');
            if (container) {
                const items = container.querySelectorAll('.ip-fqdn-item');
                items.forEach(item => {
                    const f = item.getAttribute('data-fqdn');
                    if (f) fqdns.push(f);
                });
            }
        }
        if (fqdns.length === 0) return;
        this.copyTextList(fqdns, buttonEl);
        if (typeof this.showToast === 'function') {
            this.showToast('success', `Copied ${fqdns.length} FQDNs to clipboard`);
        }
    }

    async targetAllIpFqdns(ipNodeId) {
        let fqdns = [];
        let nodeData = null;
        if (this.cy) {
            const node = this.cy.getElementById(ipNodeId);
            if (node.length > 0) {
                nodeData = node.data();
                if (Array.isArray(nodeData.fqdns)) {
                    fqdns = nodeData.fqdns;
                }
            }
        }
        if (fqdns.length === 0) {
            const container = document.getElementById('ip-fqdn-list-container');
            if (container) {
                const items = container.querySelectorAll('.ip-fqdn-item');
                items.forEach(item => {
                    const f = item.getAttribute('data-fqdn');
                    if (f) fqdns.push(f);
                });
            }
        }
        if (fqdns.length === 0) return;
        for (const fqdn of fqdns) {
            await this.setTarget(fqdn);
        }
        if (typeof this.showToast === 'function') {
            this.showToast('success', `Marked ${fqdns.length} FQDNs as targets`);
        }
        if (nodeData) {
            this.renderAssetInspector(nodeData);
        }
    }

    async loadTargets() {
        try {
            const res = await window.api.getTargets();
            if (res && Array.isArray(res.targets)) {
                this.markedTargets.clear();
                this.targetStatuses = {};
                res.targets.forEach(t => {
                    this.markedTargets.add(t.ip);
                    this.targetStatuses[t.ip] = t;
                });
                this.syncTargetNodesStyling();
                this.updateTargetBadgeCount();
                this.renderTargetsList();
            }

            // Restore historical scan logs and check if active polling is needed
            await this.loadScanLogs();
        } catch (err) {
            console.error('Failed to load targets from API:', err);
        }
    }

    async loadScanLogs() {
        try {
            const res = await window.api.getScanLogs(100);
            const consoleEl = document.getElementById('scan-live-console');
            if (consoleEl && res && Array.isArray(res.logs) && res.logs.length > 0) {
                consoleEl.innerHTML = '';
                res.logs.forEach(log => {
                    const line = document.createElement('div');
                    line.className = `console-line ${log.level || 'info'}`;
                    const timeStr = log.timestamp || '';
                    line.textContent = timeStr ? `[${timeStr}] ${log.message}` : log.message;
                    consoleEl.appendChild(line);
                });
                consoleEl.scrollTop = consoleEl.scrollHeight;
            }

            // Check if any scan is actively running in background and auto-resume polling
            const status = await window.api.getScanStatus();
            if (status && status.running_scans > 0) {
                if (Array.isArray(status.targets)) {
                    status.targets.forEach(t => {
                        this.targetStatuses[t.ip] = t;
                    });
                    this.updateTargetBadgeCount();
                    this.renderTargetsList();
                }
                this.startStatusPolling();
            }
        } catch (err) {
            console.warn('Failed to restore persistent scan logs:', err);
        }
    }

    syncTargetNodesStyling() {
        if (!this.cy) return;
        this.cy.batch(() => {
            this.cy.nodes().forEach(node => {
                if (node.id() === 'target_root' || node.data('type') === 'target' || node.data('is_root') === true) {
                    node.removeClass('is-target');
                    node.data('is_target', 'false');
                    return;
                }

                const rawName = node.data('name') || node.data('label') || node.data('ip') || node.id();
                const cleanName = String(rawName || '').replace(/^(ip_|dom_|sub_|target_)/, '').trim();
                const nodeIp = node.data('ip') ? String(node.data('ip')).trim() : '';
                const nodeLabel = node.data('label') ? String(node.data('label')).trim() : '';
                const nodeName = node.data('name') ? String(node.data('name')).trim() : '';

                const isTarget = this.markedTargets.has(cleanName) || 
                                 (nodeIp && this.markedTargets.has(nodeIp)) || 
                                 (nodeName && this.markedTargets.has(nodeName)) || 
                                 (nodeLabel && this.markedTargets.has(nodeLabel));

                if (isTarget) {
                    node.addClass('is-target');
                    node.data('is_target', 'true');
                } else {
                    node.removeClass('is-target');
                    node.data('is_target', 'false');
                }
            });
        });
        if (this.cy && typeof this.cy.style === 'function') {
            this.cy.style().update();
        }
    }

    getAssociatedIpNodes(node) {
        if (!node || !this.cy) return [];
        const nodeType = node.data('type');
        if (nodeType === 'ip') return [node];

        const ipNodes = [];
        const visited = new Set();
        const queue = [node];

        while (queue.length > 0) {
            const curr = queue.shift();
            if (!curr || visited.has(curr.id())) continue;
            visited.add(curr.id());

            const outgoers = curr.outgoers('node');
            outgoers.forEach(child => {
                if (child.data('type') === 'ip') {
                    if (!visited.has(child.id())) {
                        ipNodes.push(child);
                        visited.add(child.id());
                    }
                }
                // Continue traverse through structural hierarchy
                if (child.data('type') === 'domain' || child.data('type') === 'subdomain' || child.data('type') === 'target' || child.data('type') === 'network') {
                    if (!visited.has(child.id())) {
                        queue.push(child);
                    }
                }
            });
        }
        return ipNodes;
    }

    getAssociatedServiceNodes(node) {
        if (!node || !this.cy) return [];
        const nodeType = node.data('type');
        if (['service', 'http', 'https'].includes(nodeType)) return [node];

        const srvNodes = [];
        const ipNodes = this.getAssociatedIpNodes(node);
        const seenSrv = new Set();

        ipNodes.forEach(ipNode => {
            const outgoers = ipNode.outgoers('node[type="service"], node[type="http"], node[type="https"]');
            outgoers.forEach(sNode => {
                if (!seenSrv.has(sNode.id())) {
                    seenSrv.add(sNode.id());
                    srvNodes.push(sNode);
                }
            });
        });

        return srvNodes;
    }

    async unverifyServices(serviceNodes) {
        if (!Array.isArray(serviceNodes) || serviceNodes.length === 0) return;
        const sIds = serviceNodes.map(s => s.id());
        try {
            const data = await window.api.unverifyServices(sIds);
            if (data && data.success) {
                // Update Cytoscape node and edge states locally
                serviceNodes.forEach(sNode => {
                    sNode.data('verified_active', false);
                    sNode.data('is_active_scan', false);
                    const curSources = sNode.data('sources') || [];
                    const newSources = (Array.isArray(curSources) ? curSources : [curSources])
                        .filter(s => !String(s).toLowerCase().includes('masscan') && !String(s).toLowerCase().includes('active'));
                    if (newSources.length === 0) newSources.push('Passive');
                    sNode.data('sources', newSources);

                    // Update incoming EXPOSES edges
                    sNode.incomers('edge[label="EXPOSES"]').forEach(edge => {
                        edge.data('verified_active', false);
                        edge.data('is_active_scan', false);
                        edge.removeClass('active-scan-edge');
                    });
                });

                // Update in-memory graphData elements
                if (this.graphData && this.graphData.elements && Array.isArray(this.graphData.elements.nodes)) {
                    this.graphData.elements.nodes.forEach(n => {
                        if (sIds.includes(n.data?.id)) {
                            n.data.verified_active = false;
                            n.data.is_active_scan = false;
                            const curSources = n.data.sources || [];
                            const newSources = (Array.isArray(curSources) ? curSources : [curSources])
                                .filter(s => !String(s).toLowerCase().includes('masscan') && !String(s).toLowerCase().includes('active'));
                            if (newSources.length === 0) newSources.push('Passive');
                            n.data.sources = newSources;
                        }
                    });
                }
                if (this.graphData && this.graphData.elements && Array.isArray(this.graphData.elements.edges)) {
                    this.graphData.elements.edges.forEach(e => {
                        if (sIds.includes(e.data?.target) && e.data?.label === 'EXPOSES') {
                            e.data.verified_active = false;
                            e.data.is_active_scan = false;
                        }
                    });
                }

                // Force Cytoscape style update and re-evaluate active filters in real-time
                if (this.cy) {
                    this.cy.style().update();
                    this.applyLeadFilter({ relayout: false });
                }

                const count = data.unverified_count || serviceNodes.length;
                this.showToast('info', `Removed Verified Active from ${count} service(s). Now marked as Passive (ready for re-validation).`);

                // Re-render inspector if selected node is affected
                if (this.selectedNode) {
                    this.showNodeInspector(this.selectedNode);
                }

                // Refresh Target Management Drawer if target statuses exist
                if (typeof this.fetchTargetStatuses === 'function') {
                    await this.fetchTargetStatuses();
                }
            } else {
                this.showToast('error', (data && data.error) || 'Failed to remove Verified Active status.');
            }
        } catch (err) {
            console.error('Error unverifying services:', err);
            this.showToast('error', 'Error resetting verified active services');
        }
    }

    async setTargetsBulk(targets, nodes = []) {
        if (!Array.isArray(targets) || targets.length === 0) return;
        try {
            const cleanTargets = [];
            for (const raw of targets) {
                const clean = this.normalizeTargetId(raw);
                if (clean && clean !== 'root') {
                    this.markedTargets.add(clean);
                    if (!this.targetStatuses[clean]) {
                        this.targetStatuses[clean] = {
                            ip: clean,
                            status: 'idle',
                            nuclei_status: 'idle',
                            ports_count: 0,
                            ports: []
                        };
                    }
                    cleanTargets.push(clean);
                }
            }
            this.syncTargetNodesStyling();
            if (Array.isArray(nodes)) {
                nodes.forEach(n => {
                    if (n && typeof n.flashClass === 'function') n.flashClass('cy-selected', 400);
                });
            }
            this.updateTargetBadgeCount();
            this.renderTargetsList();
            if (this.selectedNode) {
                this.showNodeInspector(this.selectedNode);
            }
            if (typeof this.showToast === 'function') {
                this.showToast('success', `Marked ${cleanTargets.length} target(s)`);
            }
            await Promise.all(cleanTargets.map(t => window.api.setTarget(t)));
            await this.loadGraph(true);

            // Sync Lead Selector
            cleanTargets.forEach(target => {
                const targetLower = target.toLowerCase();
                const matchingLead = this.leads.find(l => {
                    const lName = (l.name || l.display_name || '').toLowerCase();
                    const lId = (l.id || '').toLowerCase();
                    return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
                });
                if (matchingLead) {
                    this.selectedLeads.add(matchingLead.id);
                }
            });
            this.applyLeadFilter({ relayout: true });
            this.renderLeadSelector();
        } catch (err) {
            console.error('Failed to set targets bulk:', err);
        }
    }

    async removeTargetsBulk(targets) {
        if (!Array.isArray(targets) || targets.length === 0) return;
        try {
            const cleanTargets = [];
            for (const raw of targets) {
                const clean = this.normalizeTargetId(raw);
                if (clean && clean !== 'root') {
                    this.markedTargets.delete(clean);
                    delete this.targetStatuses[clean];
                    cleanTargets.push(clean);
                }
            }
            this.syncTargetNodesStyling();
            this.updateTargetBadgeCount();
            this.renderTargetsList();
            if (this.selectedNode) {
                this.showNodeInspector(this.selectedNode);
            }
            if (typeof this.showToast === 'function') {
                this.showToast('info', `Removed ${cleanTargets.length} target(s) from scan list`);
            }
            await Promise.all(cleanTargets.map(t => window.api.removeTarget(t)));
            await this.loadGraph(true);

            // Sync Lead Selector
            cleanTargets.forEach(target => {
                const targetLower = target.toLowerCase();
                const matchingLead = this.leads.find(l => {
                    const lName = (l.name || l.display_name || '').toLowerCase();
                    const lId = (l.id || '').toLowerCase();
                    return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
                });
                if (matchingLead) {
                    this.selectedLeads.delete(matchingLead.id);
                }
            });
            this.applyLeadFilter({ relayout: true });
            this.renderLeadSelector();
        } catch (err) {
            console.error('Failed to remove targets bulk:', err);
        }
    }

    async setTarget(target, node = null) {
        try {
            if (node && (node.data('type') === 'target' || node.id() === 'target_root' || node.data('is_root') === true)) {
                return;
            }
            target = this.normalizeTargetId(target);
            if (!target || target === 'root') return;
            this.markedTargets.add(target);
            if (!this.targetStatuses[target]) {
                this.targetStatuses[target] = {
                    ip: target,
                    status: 'idle',
                    nuclei_status: 'idle',
                    ports_count: 0,
                    ports: []
                };
            }
            this.syncTargetNodesStyling();
            if (node) {
                node.flashClass('cy-selected', 400);
            }
            this.updateTargetBadgeCount();
            this.renderTargetsList();
            if (this.selectedNode) {
                this.showNodeInspector(this.selectedNode);
            }
            const targetLower = target.toLowerCase();
            const matchingLead = this.leads.find(l => {
                const lName = (l.name || l.display_name || '').toLowerCase();
                const lId = (l.id || '').toLowerCase();
                return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
            });
            const displayName = matchingLead ? (matchingLead.name || matchingLead.display_name || matchingLead.label || target) : target;

            if (typeof this.showToast === 'function') {
                this.showToast('success', `Target set: ${displayName}`);
            }
            await window.api.setTarget(target);
            await this.loadGraph(true);

            // Automatically activate the newly set target in the Lead Selector so it immediately renders
            if (matchingLead) {
                this.selectedLeads.add(matchingLead.id);
                this.applyLeadFilter({ relayout: true });
                this.renderLeadSelector();
            }
        } catch (err) {
            console.error(`Failed to set target ${target}:`, err);
        }
    }

    async removeTarget(target, node = null) {
        try {
            target = this.normalizeTargetId(target);
            if (!target) return;
            this.markedTargets.delete(target);
            delete this.targetStatuses[target];
            this.syncTargetNodesStyling();
            this.updateTargetBadgeCount();
            this.renderTargetsList();
            if (this.selectedNode) {
                this.showNodeInspector(this.selectedNode);
            }
            const targetLower = target.toLowerCase();
            const matchingLead = this.leads.find(l => {
                const lName = (l.name || l.display_name || '').toLowerCase();
                const lId = (l.id || '').toLowerCase();
                return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
            });
            const displayName = matchingLead ? (matchingLead.name || matchingLead.display_name || matchingLead.label || target) : target;

            if (typeof this.showToast === 'function') {
                this.showToast('info', `Target removed: ${displayName}`);
            }
            await window.api.removeTarget(target);
            await this.loadGraph(true);

            // Automatically deactivate the removed target in the Lead Selector
            if (matchingLead) {
                this.selectedLeads.delete(matchingLead.id);
                this.applyLeadFilter({ relayout: true });
                this.renderLeadSelector();
            }
        } catch (err) {
            console.error(`Failed to remove target ${target}:`, err);
        }
    }

    async clearAllTargets() {
        try {
            this.markedTargets.clear();
            this.targetStatuses = {};
            this.syncTargetNodesStyling();
            this.updateTargetBadgeCount();
            this.renderTargetsList();
            if (this.selectedNode) {
                this.showNodeInspector(this.selectedNode);
            }
            if (typeof this.showToast === 'function') {
                this.showToast('info', 'Cleared all scan targets');
            }
            await window.api.clearTargets();
            await this.loadGraph(true);
            this.addScanLog('info', 'All targets cleared.');
        } catch (err) {
            console.error('Failed to clear all targets:', err);
        }
    }

    updateTargetBadgeCount() {
        const badge = document.getElementById('target-badge-count');
        const targetBtn = document.getElementById('btn-toggle-targets');
        const scanIndicator = document.getElementById('target-scan-indicator');

        // Check if any target is currently scanning
        const isAnyMasscanRunning = Object.values(this.targetStatuses).some(t => 
            t.status === 'scanning' || t.status === 'running'
        );
        const isAnyNucleiRunning = Object.values(this.targetStatuses).some(t => 
            t.nuclei_status === 'scanning' || t.nuclei_status === 'running'
        );
        const isAnyScanning = isAnyMasscanRunning || isAnyNucleiRunning;

        if (targetBtn) {
            if (isAnyScanning) {
                targetBtn.classList.add('is-scanning');
            } else {
                targetBtn.classList.remove('is-scanning');
            }
        }

        if (scanIndicator) {
            scanIndicator.style.display = isAnyScanning ? 'inline-flex' : 'none';
        }

        // Update Masscan "Run Masscan on Targets" / "Stop Port Scan" button
        const scanAllBtn = document.getElementById('btn-scan-all-targets');
        if (scanAllBtn) {
            if (isAnyMasscanRunning) {
                scanAllBtn.classList.add('btn-scan-stopping');
                scanAllBtn.innerHTML = '<i data-lucide="square" class="ui-icon" style="width: 14px; height: 14px;"></i><span>Stop Port Scan</span>';
                scanAllBtn.title = 'Stop running Masscan port scans';
            } else {
                scanAllBtn.classList.remove('btn-scan-stopping');
                scanAllBtn.innerHTML = '<i data-lucide="play" class="ui-icon"></i><span>Run Masscan on Targets</span>';
                scanAllBtn.title = 'Run Masscan port scan on marked targets';
            }
        }

        // Update Nuclei "Run Nuclei on All Targets" / "Stop Nuclei on All" button
        const runAllNucleiBtn = document.getElementById('btn-run-all-nuclei');
        if (runAllNucleiBtn) {
            if (isAnyNucleiRunning) {
                runAllNucleiBtn.classList.add('btn-scan-stopping');
                runAllNucleiBtn.innerHTML = '<i data-lucide="square" class="ui-icon" style="width: 14px; height: 14px;"></i><span>Stop Nuclei Scan</span>';
                runAllNucleiBtn.title = 'Stop all running Nuclei scans';
            } else {
                runAllNucleiBtn.classList.remove('btn-scan-stopping');
                runAllNucleiBtn.innerHTML = '<i data-lucide="shield-alert" class="ui-icon"></i><span>Run Nuclei on All Targets</span>';
                runAllNucleiBtn.title = 'Run Nuclei vulnerability scan on all targets';
            }
        }

        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }

        if (badge) {
            const count = this.markedTargets.size;
            badge.textContent = count;
            badge.style.display = (count > 0 && !isAnyScanning) ? 'inline-block' : 'none';
        }

        const counterHeader = document.getElementById('targets-header-count');
        if (counterHeader) {
            counterHeader.textContent = `${this.markedTargets.size} Targets`;
        }
    }

    openTargetsDrawer() {
        const drawer = document.getElementById('targets-drawer');
        const backdrop = document.getElementById('targets-backdrop');
        const btn = document.getElementById('btn-toggle-targets');
        this.closeInspector();
        if (drawer) drawer.classList.add('open');
        if (backdrop) backdrop.classList.add('active');
        if (btn) btn.classList.add('active');
        this.renderTargetsList();
    }

    closeTargetsDrawer() {
        const drawer = document.getElementById('targets-drawer');
        const backdrop = document.getElementById('targets-backdrop');
        const btn = document.getElementById('btn-toggle-targets');
        if (drawer) drawer.classList.remove('open');
        if (backdrop) backdrop.classList.remove('active');
        if (btn) btn.classList.remove('active');
    }

    toggleTargetsDrawer() {
        const drawer = document.getElementById('targets-drawer');
        if (drawer && drawer.classList.contains('open')) {
            this.closeTargetsDrawer();
        } else {
            this.openTargetsDrawer();
        }
    }

    renderTargetsList() {
        const emptyState = document.getElementById('targets-empty-state');
        const itemsList = document.getElementById('targets-items-list');
        if (!itemsList || !emptyState) return;

        if (this.markedTargets.size === 0) {
            emptyState.style.display = 'flex';
            itemsList.style.display = 'none';
            itemsList.innerHTML = '';
            return;
        }

        emptyState.style.display = 'none';
        itemsList.style.display = 'flex';

        const targetsHtml = Array.from(this.markedTargets).map(ip => {
            const statusObj = this.targetStatuses[ip] || { status: 'idle', nuclei_status: 'idle', ports_count: 0 };
            
            let displayName = ip;
            if (this.leads && Array.isArray(this.leads)) {
                const lead = this.leads.find(l => l.display_name === ip || l.label === ip || l.name === ip);
                if (lead) displayName = lead.display_name || lead.label || ip;
            } else if (this.nodeIndex) {
                let node = null;
                for (const [id, n] of this.nodeIndex.entries()) {
                    if (n.display_name === ip || n.label === ip || n.name === ip || n.ip === ip) {
                        node = n;
                        break;
                    }
                }
                if (node) displayName = node.display_name || node.label || node.name || node.ip || ip;
            }
            const status = statusObj.status || 'idle';
            const nucleiStatus = statusObj.nuclei_status || 'idle';
            const portsCount = statusObj.ports_count || (Array.isArray(statusObj.ports) ? statusObj.ports.length : 0);
            const vulnsCount = statusObj.vulns_count || 0;
            const isScanningPorts = status === 'scanning' || status === 'running';
            const isScanningNuclei = nucleiStatus === 'scanning' || nucleiStatus === 'running';
            const isAnyScanning = isScanningPorts || isScanningNuclei;

            const portsList = Array.isArray(statusObj.ports) ? statusObj.ports : [];
            const portsTagsHtml = portsList.length > 0 ? `
                <div class="target-card-ports-chips" style="display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.4rem;">
                    ${portsList.slice(0, 8).map(p => {
                        const pNum = p.port;
                        const pProto = p.protocol || 'tcp';
                        const pBanner = p.banner ? p.banner.trim() : '';
                        const pTooltip = pBanner ? `Port ${pNum}/${pProto} - Banner: ${pBanner.substring(0, 100)}` : `Port ${pNum}/${pProto} (${p.service_name || 'open'})`;
                        return `<span class="port-chip" style="background: rgba(168, 85, 247, 0.18); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.35); padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.72rem; font-family: var(--font-mono, monospace);" title="${this.escapeHtml(pTooltip)}">${pNum}/${pProto}</span>`;
                    }).join('')}
                    ${portsList.length > 8 ? `<span style="color: var(--text-muted); font-size: 0.7rem; align-self: center;">+${portsList.length - 8} more</span>` : ''}
                </div>
            ` : '';

            return `
                <div class="target-card-item" data-ip="${ip}">
                    <div class="target-card-left">
                        <div class="target-card-ip-row">
                            <span class="target-card-ip">${displayName}</span>
                            <span class="target-status-tag ${status}" title="Port Scan: ${status}">${status}</span>
                            ${nucleiStatus !== 'idle' ? `<span class="target-status-tag ${nucleiStatus}" style="border-color: rgba(239, 68, 68, 0.5); color: #f87171;" title="Nuclei: ${nucleiStatus}">Nuclei: ${nucleiStatus}</span>` : ''}
                        </div>
                        <div class="target-card-meta" style="display: flex; gap: 0.75rem; font-size: 0.74rem; color: var(--text-secondary); margin-top: 0.2rem;">
                            <span>Ports: <strong style="color: #00f0ff;">${portsCount}</strong></span>
                            <span>Vulns: <strong style="color: #f87171;">${vulnsCount}</strong></span>
                            ${statusObj.error ? `<span style="color: #ef4444;" title="${this.escapeHtml(statusObj.error)}">Error</span>` : ''}
                        </div>
                        ${portsTagsHtml}
                    </div>
                    <div class="target-actions-btns">
                        ${isScanningPorts ? `
                            <button type="button" class="btn-target-scan-mini" title="Cancel Port Scan" onclick="window.dashboard.cancelActiveScan('${ip}', 'masscan')">
                                <i data-lucide="square" class="ui-icon" style="width: 12px; height: 12px; color: #f59e0b;"></i>
                                <span>Stop</span>
                            </button>
                        ` : `
                            <button type="button" class="btn-target-scan-mini port-scan" title="Scan Ports (Masscan)" onclick="window.dashboard.startActiveScan('${ip}')">
                                <i data-lucide="play" class="ui-icon" style="width: 12px; height: 12px;"></i>
                                <span>Ports</span>
                            </button>
                        `}
                        ${isScanningNuclei ? `
                            <button type="button" class="btn-target-scan-mini" title="Cancel Nuclei Scan" onclick="window.dashboard.cancelActiveScan('${ip}', 'nuclei')">
                                <i data-lucide="square" class="ui-icon" style="width: 12px; height: 12px; color: #ef4444;"></i>
                                <span>Stop</span>
                            </button>
                        ` : `
                            <button type="button" class="btn-target-scan-mini nuclei-scan" title="Scan Vulns (Nuclei)" onclick="window.dashboard.startNucleiScan('${ip}')">
                                <i data-lucide="shield-alert" class="ui-icon" style="width: 12px; height: 12px;"></i>
                                <span>Vulns</span>
                            </button>
                        `}
                        <button type="button" class="btn-target-remove-mini" title="Remove target" onclick="window.dashboard.removeTarget('${ip}')">
                            <i data-lucide="trash-2" class="ui-icon" style="width: 14px; height: 14px;"></i>
                        </button>
                    </div>
                </div>
            `;
        }).join('');

        itemsList.innerHTML = targetsHtml;
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }

    setupTargetManagement() {
        const toggleBtn = document.getElementById('btn-toggle-targets');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggleTargetsDrawer();
            });
        }

        const closeBtn = document.getElementById('close-targets-drawer');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                this.closeTargetsDrawer();
            });
        }

        const backdrop = document.getElementById('targets-backdrop');
        if (backdrop) {
            backdrop.addEventListener('click', () => {
                this.closeTargetsDrawer();
            });
        }

        // Drawer Tabs Switching
        const tabBtns = document.querySelectorAll('.drawer-tab-btn');
        const tabPanes = {
            'targets-tab': document.getElementById('tab-pane-targets'),
            'masscan-tab': document.getElementById('tab-pane-masscan'),
            'nuclei-tab': document.getElementById('tab-pane-nuclei'),
        };

        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetTab = btn.getAttribute('data-tab');
                tabBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                Object.keys(tabPanes).forEach(k => {
                    if (tabPanes[k]) {
                        tabPanes[k].style.display = (k === targetTab) ? 'flex' : 'none';
                    }
                });
            });
        });

        // Scan All Ports button (toggles start vs stop)
        const scanAllBtn = document.getElementById('btn-scan-all-targets');
        if (scanAllBtn) {
            scanAllBtn.addEventListener('click', () => {
                const isRunning = Object.values(this.targetStatuses).some(t => 
                    t.status === 'scanning' || t.status === 'running'
                );
                if (isRunning) {
                    this.cancelActiveScan(null, 'masscan');
                } else {
                    this.startActiveScan();
                }
            });
        }

        // Run Nuclei on All Targets button (toggles start vs stop)
        const runAllNucleiBtn = document.getElementById('btn-run-all-nuclei');
        if (runAllNucleiBtn) {
            runAllNucleiBtn.addEventListener('click', () => {
                const isRunning = Object.values(this.targetStatuses).some(t => 
                    t.nuclei_status === 'scanning' || t.nuclei_status === 'running'
                );
                if (isRunning) {
                    this.cancelActiveScan(null, 'nuclei');
                } else {
                    this.startNucleiScan();
                }
            });
        }

        const clearAllBtn = document.getElementById('btn-clear-all-targets');
        if (clearAllBtn) {
            clearAllBtn.addEventListener('click', () => {
                this.clearAllTargets();
            });
        }

        // Clear logs button
        const clearLogsBtn = document.getElementById('btn-clear-scan-logs');
        if (clearLogsBtn) {
            clearLogsBtn.addEventListener('click', () => {
                const consoleEl = document.getElementById('scan-live-console');
                if (consoleEl) {
                    consoleEl.innerHTML = '<div class="console-line info">[System] Log console cleared.</div>';
                }
            });
        }

        // Preset buttons for Masscan
        const presetBtns = document.querySelectorAll('.preset-btn');
        const customPortsGroup = document.getElementById('custom-ports-group');
        presetBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                presetBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.currentPortPreset = btn.getAttribute('data-preset') || 'top100';
                if (customPortsGroup) {
                    customPortsGroup.style.display = this.currentPortPreset === 'custom' ? 'flex' : 'none';
                }
            });
        });

        // Rate slider for Masscan
        const rateSlider = document.getElementById('input-scan-rate');
        const rateDisplay = document.getElementById('scan-rate-display');
        if (rateSlider && rateDisplay) {
            rateSlider.addEventListener('input', (e) => {
                rateDisplay.textContent = `${e.target.value} pps`;
            });
        }
    }

    async startActiveScan(specificTarget = null) {
        const targets = specificTarget ? [specificTarget] : Array.from(this.markedTargets);
        if (targets.length === 0) {
            this.addScanLog('warning', 'No targets marked for scanning.');
            return;
        }

        // Switch to logs tab or show feedback
        this.switchToLogsTab();

        try {
            const perm = await window.api.checkScanPermissions();
            if (perm.masscan && !perm.masscan.available) {
                this.addScanLog('error', 'Masscan executable not found on system. Please install masscan.');
                return;
            }
        } catch (e) {
            console.warn('Could not verify scan permissions:', e);
        }

        const customPortsInput = document.getElementById('input-custom-ports');
        const rateSlider = document.getElementById('input-scan-rate');
        const pnCheckbox = document.getElementById('chk-scan-pn');
        const bannersCheckbox = document.getElementById('chk-scan-banners');
        const extraFlagsInput = document.getElementById('input-extra-flags');

        let portsValue = '--top-ports 100';
        if (this.currentPortPreset === 'custom' && customPortsInput) {
            portsValue = customPortsInput.value || '--top-ports 100';
        } else if (this.currentPortPreset === 'all') {
            portsValue = '-p0-65535';
        } else if (this.currentPortPreset === 'web') {
            portsValue = '-p80,443,8080,8443,8000,8888,9000,9443';
        }

        const config = {
            targets: targets,
            preset: this.currentPortPreset || 'top100',
            ports: portsValue,
            rate: rateSlider ? parseInt(rateSlider.value) : 1000,
            disable_ping: pnCheckbox ? pnCheckbox.checked : true,
            banners: bannersCheckbox ? bannersCheckbox.checked : true,
            custom_flags: extraFlagsInput ? extraFlagsInput.value : ''
        };

        targets.forEach(ip => {
            if (!this.targetStatuses[ip]) {
                this.targetStatuses[ip] = { ip: ip, status: 'scanning', ports_count: 0 };
            } else {
                this.targetStatuses[ip].status = 'scanning';
            }
        });
        this.updateTargetBadgeCount();
        this.renderTargetsList();

        this.addScanLog('info', `Dispatching Masscan active port scan for ${targets.length} target(s) [${config.preset}]...`);

        try {
            const res = await window.api.startActiveScan(config);
            if (res.success) {
                this.addScanLog('success', res.message || 'Port scan running in background.');
                this.startStatusPolling();
            } else {
                this.addScanLog('error', res.detail || 'Failed to start active port scan.');
            }
        } catch (err) {
            this.addScanLog('error', `Error starting active scan: ${err.message}`);
        }
    }

    async startNucleiScan(specificTarget = null) {
        const targets = specificTarget ? [specificTarget] : Array.from(this.markedTargets);
        if (targets.length === 0) {
            this.addScanLog('warning', 'No targets marked for Nuclei scanning.');
            return;
        }

        this.switchToLogsTab();

        try {
            const perm = await window.api.checkScanPermissions();
            if (perm.nuclei && !perm.nuclei.available) {
                this.addScanLog('error', 'Nuclei binary not found on system. Please install Nuclei.');
                return;
            }
        } catch (e) {
            console.warn('Could not verify Nuclei permissions:', e);
        }

        // Collect selected severities
        const severities = [];
        if (document.getElementById('chk-nuclei-sev-critical')?.checked) severities.push('critical');
        if (document.getElementById('chk-nuclei-sev-high')?.checked) severities.push('high');
        if (document.getElementById('chk-nuclei-sev-medium')?.checked) severities.push('medium');
        if (document.getElementById('chk-nuclei-sev-low')?.checked) severities.push('low');
        if (document.getElementById('chk-nuclei-sev-info')?.checked) severities.push('info');

        // Collect selected tags
        const tags = [];
        document.querySelectorAll('.chk-nuclei-tag:checked').forEach(chk => {
            tags.push(chk.value);
        });

        const customTagsInput = document.getElementById('input-nuclei-custom-tags');
        const rateLimitInput = document.getElementById('input-nuclei-rate-limit');
        const concurrencyInput = document.getElementById('input-nuclei-concurrency');
        const customFlagsInput = document.getElementById('input-nuclei-custom-flags');

        const config = {
            targets: targets,
            severities: severities.length > 0 ? severities : ['critical', 'high'],
            tags: tags,
            custom_tags: customTagsInput ? customTagsInput.value : '',
            rate_limit: rateLimitInput ? parseInt(rateLimitInput.value) : 150,
            concurrency: concurrencyInput ? parseInt(concurrencyInput.value) : 25,
            custom_flags: customFlagsInput ? customFlagsInput.value : ''
        };

        targets.forEach(ip => {
            if (!this.targetStatuses[ip]) {
                this.targetStatuses[ip] = { ip: ip, nuclei_status: 'scanning', vulns_count: 0 };
            } else {
                this.targetStatuses[ip].nuclei_status = 'scanning';
            }
        });
        this.updateTargetBadgeCount();
        this.renderTargetsList();

        this.addScanLog('info', `[Nuclei] Dispatching vulnerability scan on ${targets.length} target(s) [Severities: ${config.severities.join(', ')}]...`);

        try {
            const res = await window.api.startNucleiScan(config);
            if (res.success) {
                this.addScanLog('success', res.message || 'Nuclei scan started.');
                this.startStatusPolling();
            } else {
                this.addScanLog('error', res.detail || 'Failed to start Nuclei scan.');
            }
        } catch (err) {
            this.addScanLog('error', `Error starting Nuclei scan: ${err.message}`);
        }
    }

    switchToLogsTab() {
        const targetsTabBtn = document.querySelector('.drawer-tab-btn[data-tab="targets-tab"]');
        if (targetsTabBtn) {
            targetsTabBtn.click();
        }
        const consoleEl = document.getElementById('scan-live-console');
        if (consoleEl) {
            consoleEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    async cancelActiveScan(target = null, scanType = 'all') {
        try {
            await window.api.cancelActiveScan(target, target === null, scanType);
            this.addScanLog('warning', target ? `Cancelled ${scanType} scan on ${target}` : `Cancelled all ${scanType} scans.`);
            if (target && this.targetStatuses[target]) {
                if (scanType === 'all' || scanType === 'masscan') this.targetStatuses[target].status = 'idle';
                if (scanType === 'all' || scanType === 'nuclei') this.targetStatuses[target].nuclei_status = 'idle';
            } else if (!target) {
                Object.keys(this.targetStatuses).forEach(ip => {
                    if (scanType === 'all' || scanType === 'masscan') this.targetStatuses[ip].status = 'idle';
                    if (scanType === 'all' || scanType === 'nuclei') this.targetStatuses[ip].nuclei_status = 'idle';
                });
            }
            this.updateTargetBadgeCount();
            this.renderTargetsList();
        } catch (err) {
            console.error('Failed to cancel scan:', err);
        }
    }

    startStatusPolling() {
        if (this.scanPollingInterval) return;

        this.scanPollingInterval = setInterval(async () => {
            try {
                const status = await window.api.getScanStatus();
                if (status && Array.isArray(status.targets)) {
                    status.targets.forEach(t => {
                        this.targetStatuses[t.ip] = t;
                    });
                    this.updateTargetBadgeCount();
                    this.renderTargetsList();

                    if (Array.isArray(status.recent_logs) && status.recent_logs.length > 0) {
                        const lastLog = status.recent_logs[status.recent_logs.length - 1];
                        this.addScanLog(lastLog.level, `[${lastLog.timestamp}] ${lastLog.message}`, false);
                    }

                    // If no scans running, finish polling and refresh graph
                    if (status.running_scans === 0) {
                        clearInterval(this.scanPollingInterval);
                        this.scanPollingInterval = null;
                        this.updateTargetBadgeCount();
                        this.addScanLog('success', 'All scan tasks completed. Refreshing attack surface graph & metrics...');
                        await this.loadSummary();
                        await this.loadGraph(true);
                    }
                }
            } catch (e) {
                console.warn('Status polling error:', e);
            }
        }, 1500);
    }

    addScanLog(level, message, dedupe = true) {
        const consoleEl = document.getElementById('scan-live-console');
        if (!consoleEl) return;

        const timeStr = new Date().toLocaleTimeString();
        const line = document.createElement('div');
        line.className = `console-line ${level}`;
        line.textContent = `[${timeStr}] ${message}`;

        if (dedupe && consoleEl.lastElementChild && consoleEl.lastElementChild.textContent.includes(message)) {
            return;
        }

        consoleEl.appendChild(line);
        consoleEl.scrollTop = consoleEl.scrollHeight;
    }

    escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    async loadRootAuditLogs(target = '', forceRefresh = false) {
        const container = document.getElementById('root-audit-logs-container');
        const countEl = document.getElementById('root-audit-logs-count');
        if (!container) return;

        if (this._rootAuditLogsCache && !forceRefresh) {
            this.renderRootAuditLogs(this._rootAuditLogsCache);
            return;
        }

        container.innerHTML = '<div style="color: #64748b; font-style: italic;">Fetching CLI audit trail from SQLite database...</div>';
        if (countEl) countEl.textContent = '...';

        try {
            const data = await window.api.getScanLogs(300, target || null);
            const logs = Array.isArray(data.logs) ? data.logs : [];
            this._rootAuditLogsCache = logs;
            this.renderRootAuditLogs(logs);
        } catch (err) {
            console.error('Failed to load root audit logs:', err);
            container.innerHTML = `<div style="color: #ef4444;">Failed to load audit logs: ${this.escapeHtml(err.message)}</div>`;
            if (countEl) countEl.textContent = '0';
        }
    }

    renderRootAuditLogs(logs) {
        const container = document.getElementById('root-audit-logs-container');
        const countEl = document.getElementById('root-audit-logs-count');
        if (!container) return;

        if (countEl) countEl.textContent = logs.length;

        if (!logs || logs.length === 0) {
            container.innerHTML = '<div style="color: #64748b; font-style: italic;">No CLI execution logs recorded for this target yet.</div>';
            return;
        }

        const linesHtml = logs.map(l => {
            const lvl = String(l.level || 'info').toLowerCase();
            let color = '#94a3b8';
            if (lvl.includes('error') || lvl.includes('crit')) color = '#ef4444';
            else if (lvl.includes('warn')) color = '#f59e0b';
            else if (lvl.includes('success')) color = '#10b981';
            else if (lvl.includes('info')) color = '#00f0ff';

            const timeStr = l.timestamp ? `[${this.escapeHtml(l.timestamp)}]` : '';
            const inputTargetStr = l.input_target ? `<span style="background: rgba(140, 82, 255, 0.15); color: #c084fc; border: 1px solid rgba(140, 82, 255, 0.4); border-radius: 4px; padding: 0 4px; font-size: 0.65rem; margin-right: 6px;">🎯 ${this.escapeHtml(l.input_target)}</span>` : '';
            return `<div class="root-log-line" data-msg="${this.escapeHtml((l.message || '').toLowerCase())} ${this.escapeHtml((l.input_target || '').toLowerCase())}" style="margin-bottom: 2px;">
                <span style="color: #64748b; margin-right: 4px;">${timeStr}</span>
                ${inputTargetStr}
                <span style="color: ${color}; font-weight: 600; margin-right: 6px;">[${this.escapeHtml(lvl.toUpperCase())}]</span>
                <span style="color: #f1f5f9;">${this.escapeHtml(l.message || '')}</span>
            </div>`;
        }).join('');

        container.innerHTML = linesHtml;
        container.scrollTop = container.scrollHeight;
    }

    filterRootAuditLogs(query) {
        const q = String(query || '').toLowerCase().trim();
        const lines = document.querySelectorAll('#root-audit-logs-container .root-log-line');
        let visibleCount = 0;
        lines.forEach(el => {
            const msg = el.getAttribute('data-msg') || el.textContent.toLowerCase();
            if (!q || msg.includes(q)) {
                el.style.display = '';
                visibleCount++;
            } else {
                el.style.display = 'none';
            }
        });
        const countEl = document.getElementById('root-audit-logs-count');
        if (countEl) countEl.textContent = visibleCount;
    }

    copyRootAuditLogs(btnElement) {
        const logs = this._rootAuditLogsCache || [];
        if (logs.length === 0) {
            this.showToast('info', 'No logs available to copy');
            return;
        }
        const textToCopy = logs.map(l => `[${l.timestamp || ''}] [${String(l.level || 'INFO').toUpperCase()}] ${l.message || ''}`).join('\n');
        this.copyTextList(textToCopy, btnElement);
    }

    updateLayoutSelector() {
        const layoutSelect = document.getElementById('layout-select');
        if (layoutSelect) {
            const availableLayout = this.getAvailableLayout();
            layoutSelect.value = availableLayout;
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing dashboard...');
    
    // Check if required libraries are loaded
    if (typeof cytoscape === 'undefined') {
        console.error('Cytoscape.js not loaded');
        return;
    }
    
    // Wait a bit for API client to be ready
    setTimeout(() => {
        window.dashboard = new EASMDashboard();
        window.dashboard.init();
    }, 100);
});

