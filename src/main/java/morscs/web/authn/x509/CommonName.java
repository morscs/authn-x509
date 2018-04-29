/*
 *  CommonName.java
 *
 *    Copyright 2018 Moriarty Software & Consulting Services
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

package morscs.web.authn.x509;

public class CommonName {

  private final String firstName;
  private final String lastName;
  private final String middleName;
  private final long edipi;

  /**
   * Construct common name object.
   *
   * @param edipi 10 digit edipi identifier
   * @param lastName last name
   * @param firstName first name
   * @param middle middle name or null if unavailable
   */
  public CommonName(long edipi, String lastName, String firstName, String middle) {
    this.edipi = edipi;
    this.lastName = lastName;
    this.firstName = firstName;
    this.middleName = middle;
  }

  public String getFirstName() {
    return firstName;
  }

  public String getLastName() {
    return lastName;
  }

  public String getMiddleName() {
    return middleName;
  }

  public long getEdipi() {
    return edipi;
  }
}
