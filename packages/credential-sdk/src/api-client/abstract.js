/**
 * Abstract base class for API clients
 * Provides common functionality for making HTTP requests to external services
 */
class AbstractApiClient {
    /**
     * @param {string} baseUrl - Base URL of the API service
     * @param {object} [options] - Additional options
     * @param {object} [options.headers] - Default headers for all requests
     * @param {number} [options.timeout] - Request timeout in milliseconds
     */
    constructor(baseUrl, options = {}) {
        if (!baseUrl) {
            throw new Error('Base URL is required');
        }

        this.baseUrl = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
        this.defaultHeaders = options.headers || {};
        this.timeout = options.timeout || 30000; // 30 seconds default
    }

    /**
     * Make a GET request
     * @param {string} endpoint - API endpoint (without base URL)
     * @param {object} [params] - Query parameters
     * @param {object} [headers] - Additional headers for this request
     * @returns {Promise<any>} Response data
     * @protected
     */
    async get(endpoint, params = {}, headers = {}) {
        return this._request('GET', endpoint, null, params, headers);
    }

    /**
     * Make a POST request
     * @param {string} endpoint - API endpoint (without base URL)
     * @param {object} [data] - Request body
     * @param {object} [headers] - Additional headers for this request
     * @returns {Promise<any>} Response data
     * @protected
     */
    async post(endpoint, data = null, headers = {}) {
        return this._request('POST', endpoint, data, {}, headers);
    }

    /**
     * Make a PUT request
     * @param {string} endpoint - API endpoint (without base URL)
     * @param {object} [data] - Request body
     * @param {object} [headers] - Additional headers for this request
     * @returns {Promise<any>} Response data
     * @protected
     */
    async put(endpoint, data = null, headers = {}) {
        return this._request('PUT', endpoint, data, {}, headers);
    }

    /**
     * Make a DELETE request
     * @param {string} endpoint - API endpoint (without base URL)
     * @param {object} [headers] - Additional headers for this request
     * @returns {Promise<any>} Response data
     * @protected
     */
    async delete(endpoint, headers = {}) {
        return this._request('DELETE', endpoint, null, {}, headers);
    }

    /**
     * Internal method to make HTTP requests
     * @param {string} method - HTTP method
     * @param {string} endpoint - API endpoint
     * @param {object} [data] - Request body
     * @param {object} [params] - Query parameters
     * @param {object} [headers] - Additional headers
     * @returns {Promise<any>} Response data
     * @private
     */
    async _request(method, endpoint, data = null, params = {}, headers = {}) {
        const url = new URL(`${this.baseUrl}${endpoint}`);

        // Add query parameters
        Object.keys(params).forEach(key => {
            if (params[key] !== undefined && params[key] !== null) {
                url.searchParams.append(key, params[key]);
            }
        });

        const requestOptions = {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...this.defaultHeaders,
                ...headers,
            },
        };

        // Add body for POST, PUT requests
        if (data && (method === 'POST' || method === 'PUT')) {
            requestOptions.body = JSON.stringify(data);
        }

        // Create abort controller for timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        requestOptions.signal = controller.signal;

        try {
            const response = await fetch(url.toString(), requestOptions);
            clearTimeout(timeoutId);

            // Handle non-OK responses
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(
                    errorData.message || `HTTP ${response.status}: ${response.statusText}`
                );
            }

            // Parse JSON response
            const responseData = await response.json();
            return responseData;
        } catch (error) {
            clearTimeout(timeoutId);

            if (error.name === 'AbortError') {
                throw new Error(`Request timeout after ${this.timeout}ms`);
            }

            throw error;
        }
    }

    /**
     * Validate required parameters
     * @param {object} params - Parameters to validate
     * @param {string[]} required - Required parameter names
     * @throws {Error} If any required parameter is missing
     * @protected
     */
    _validateParams(params, required) {
        const missing = required.filter(key => !params[key]);
        if (missing.length > 0) {
            throw new Error(`Missing required parameters: ${missing.join(', ')}`);
        }
    }
}

export default AbstractApiClient;
